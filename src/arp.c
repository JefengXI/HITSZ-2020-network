#include "arp.h"
#include "utils.h"
#include "ethernet.h"
#include "config.h"
#include <string.h>
#include <stdio.h>
#include <sys/time.h>

/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type = swap16(ARP_HW_ETHER),
    .pro_type = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = DRIVER_IF_IP,
    .sender_mac = DRIVER_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表
 * 
 */
arp_entry_t arp_table[ARP_MAX_ENTRY];

/**
 * @brief 长度为1的arp分组队列，当等待arp回复时暂存未发送的数据包
 * 
 */
arp_buf_t arp_buf;

/**
 * @brief 更新arp表
 *        你首先需要依次轮询检测ARP表中所有的ARP表项是否有超时，如果有超时，则将该表项的状态改为无效。
 *        接着，查看ARP表是否有无效的表项，如果有，则将arp_update()函数传递进来的新的IP、MAC信息插入到表中，
 *        并记录超时时间，更改表项的状态为有效。
 *        如果ARP表中没有无效的表项，则找到超时时间最长的一条表项，
 *        将arp_update()函数传递进来的新的IP、MAC信息替换该表项，并记录超时时间，设置表项的状态为有效。
 * 
 * @param ip ip地址
 * @param mac mac地址
 * @param state 表项的状态
 */
#define TTL 30
void arp_update(uint8_t *ip, uint8_t *mac, arp_state_t state)
{   
    // TODO
    struct timeval time;
    gettimeofday(&time, NULL);
    long sec = time.tv_sec;
  
    for(int i=0; i<ARP_MAX_ENTRY; i++){
        if(sec - arp_table[i].timeout > TTL){
            //timeout > TTL = 30
            arp_table[i].state = ARP_INVALID;
        } 
    }

    int flag = 0;
    for(int i=0; i<ARP_MAX_ENTRY; i++){
        if(arp_table[i].state == ARP_INVALID){
            arp_table[i].state = ARP_VALID;
            arp_table[i].timeout = sec;
            memcpy(arp_table[i].ip,ip,NET_IP_LEN);
            memcpy(arp_table[i].mac,mac,NET_MAC_LEN);
            flag = 1;
            break;
        }
    }

    if(flag==0){
        int max_timeout = 0, index = 0;
        for(int i=0; i<ARP_MAX_ENTRY; i++){
            if(sec - arp_table[i].timeout > max_timeout){
                max_timeout = sec - arp_table[i].timeout;
                index = i;
        }
        arp_table[index].state = ARP_VALID;
        arp_table[index].timeout = sec;
        memcpy(arp_table[index].ip,ip,NET_IP_LEN);
        memcpy(arp_table[index].mac,mac,NET_MAC_LEN);
        }
    }
}

/**
 * @brief 从arp表中根据ip地址查找mac地址
 * 
 * @param ip 欲转换的ip地址
 * @return uint8_t* mac地址，未找到时为NULL
 */
static uint8_t *arp_lookup(uint8_t *ip)
{
    for (int i = 0; i < ARP_MAX_ENTRY; i++)
        if (arp_table[i].state == ARP_VALID && memcmp(arp_table[i].ip, ip, NET_IP_LEN) == 0)
            return arp_table[i].mac;
    return NULL;
}

/**
 * @brief 发送一个arp请求
 *        你需要调用buf_init对txbuf进行初始化
 *        填写ARP报头，将ARP的opcode设置为ARP_REQUEST，注意大小端转换
 *        将ARP数据报发送到ethernet层
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
static void arp_req(uint8_t *target_ip)
{
    // TODO
    buf_init(&txbuf,28);
    uint8_t *p = &txbuf.data[0];
    //硬件类型
    p[0] = 0x00; p[1] = ARP_HW_ETHER;
    //上层协议类型:IP
    p[2] = 0x08; p[3] = 0x00;
    //MAC 地址长度
    p[4] = 0x06;
    //IP 协议地址长度
    p[5] = 0x04;
    //操作类型:request
    p[6] = 0x00; p[7] = ARP_REQUEST;

    uint8_t if_mac[] = DRIVER_IF_MAC;
    uint8_t if_ip[] = DRIVER_IF_IP;
    //源MAC
    p += 8;
    memcpy(p,if_mac,NET_MAC_LEN);
    //源IP
    p += 6;
    memcpy(p,if_ip,NET_IP_LEN);
    //目的 MAC
    p += 6;
    memset(p,0x00,NET_MAC_LEN * sizeof(uint8_t));
    //目的 IP
    p += 4;
    memcpy(p,target_ip,NET_IP_LEN);
    //调用 ethernet_out 函数将 ARP 报文发送出去
    const uint8_t mac_broadcast[] = {0xff,0xff,0xff,0xff,0xff,0xff};
    ethernet_out(&txbuf, mac_broadcast, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *        你首先需要做报头检查，查看报文是否完整，
 *        检查项包括：硬件类型，协议类型，硬件地址长度，协议地址长度，操作类型
 *        
 *        接着，调用arp_update更新ARP表项
 *        查看arp_buf是否有效，如果有效，则说明ARP分组队列里面有待发送的数据包。
 *        即上一次调用arp_out()发送来自IP层的数据包时，由于没有找到对应的MAC地址进而先发送的ARP request报文
 *        此时，收到了该request的应答报文。然后，根据IP地址来查找ARM表项，如果能找到该IP地址对应的MAC地址，
 *        则将缓存的数据包arp_buf再发送到ethernet层。
 * 
 *        如果arp_buf无效，还需要判断接收到的报文是否为request请求报文，并且，该请求报文的目的IP正好是本机的IP地址，
 *        则认为是请求本机MAC地址的ARP请求报文，则回应一个响应报文（应答报文）。
 *        响应报文：需要调用buf_init初始化一个buf，填写ARP报头，目的IP和目的MAC需要填写为收到的ARP报的源IP和源MAC。
 * 
 * @param buf 要处理的数据包
 */
void arp_in(buf_t *buf)
{
    uint8_t *pr = &buf->data[0];
    uint8_t *sor_mac = pr+8;
    uint8_t *sor_ip = pr+14;
    uint8_t *dst_mac = pr+18;
    uint8_t *dst_ip = pr+24;
    arp_update(sor_ip,sor_mac,ARP_VALID);
    if(arp_buf.valid){
        arp_lookup(sor_ip);
        ethernet_out(&arp_buf.buf,sor_mac,arp_buf.protocol);
        arp_buf.valid = 0;
    }
    else{
        uint8_t if_mac[] = DRIVER_IF_MAC;
        uint8_t if_ip[] = DRIVER_IF_IP;
        if(pr[7]==ARP_REQUEST && memcmp(dst_ip, if_ip, NET_IP_LEN) == 0){
            buf_init(&txbuf,28);
            uint8_t *p = &txbuf.data[0];
            //硬件类型
            p[0] = 0x00; p[1] = ARP_HW_ETHER;
            //上层协议类型:IP
            p[2] = 0x08; p[3] = 0x00;
            //MAC 地址长度
            p[4] = 0x06;
            //IP 协议地址长度
            p[5] = 0x04;
            //操作类型:reply
            p[6] = 0x00; p[7] = ARP_REPLY;
            //源MAC
            p += 8;
            memcpy(p,if_mac,NET_MAC_LEN);
            //源IP
            p += 6;
            memcpy(p,if_ip,NET_IP_LEN);
            //目的 MAC
            p += 4;
            memcpy(p,sor_mac,NET_MAC_LEN);
            //目的 IP
            p += 6;
            memcpy(p,sor_ip,NET_IP_LEN);
            //调用 ethernet_out 函数将 ARP 报文发送出去
            ethernet_out(&txbuf, sor_mac, NET_PROTOCOL_ARP);
        }
    }
    

    
}

/**
 * @brief 处理一个要发送的数据包
 *        你需要根据IP地址来查找ARP表
 *        如果能找到该IP地址对应的MAC地址，则将数据报直接发送给ethernet层
 *        如果没有找到对应的MAC地址，则需要先发一个ARP request报文。
 *        注意，需要将来自IP层的数据包缓存到arp_buf中，等待arp_in()能收到ARP request报文的应答报文
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{   
    uint8_t *mac = arp_lookup(ip);
    if(mac != NULL){
        ethernet_out(buf,mac,protocol);
    }
    else{
        arp_req(ip);
        //将来自IP层的数据包缓存到arp_buf的buf中
        arp_buf.valid = ARP_VALID;
        // arp_buf.buf = buf;
        buf_copy(&arp_buf.buf,buf);
        memcpy(arp_buf.ip,ip,NET_IP_LEN);
        arp_buf.protocol = protocol;
    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    for (int i = 0; i < ARP_MAX_ENTRY; i++)
        arp_table[i].state = ARP_INVALID;
    arp_buf.valid = 0;
    arp_req(net_if_ip);
}