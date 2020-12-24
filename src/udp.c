#include "udp.h"
#include "ip.h"
#include "icmp.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define UDP_PESO_LEN 12
udp_hdr_t udp_hdr;

/**
 * @brief udp处理程序表
 * 
 */
static udp_entry_t udp_table[UDP_MAX_HANDLER];

/**
 * @brief 从udp表中查找dest_port
 * 
 * @param dest_port 欲查找的dest_port
 * @return int 找到时为对应索引i,未找到时为-1
 */
static int udp_lookup(int dest_port)
{
    for (int i = 0; i < UDP_MAX_HANDLER; i++)
        if (udp_table[i].valid == 1 && udp_table[i].port == dest_port)
            return i;
    return -1;
}

/**
 * @brief udp伪校验和计算
 *        1. 你首先调用buf_add_header()添加UDP伪头部
 *        2. 将IP头部拷贝出来，暂存被UDP伪头部覆盖的IP头部
 *        3. 填写UDP伪头部的12字节字段
 *        4. 计算UDP校验和，注意：UDP校验和覆盖了UDP头部、UDP数据和UDP伪头部
 *        5. 再将暂存的IP头部拷贝回来
 *        6. 调用buf_remove_header()函数去掉UDP伪头部
 *        7. 返回计算后的校验和。  
 * 
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dest_ip 目的ip地址
 * @return uint16_t 伪校验和
 */
static uint16_t udp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dest_ip)
{   
    //添加UDP伪头部
    buf_add_header(buf,UDP_PESO_LEN);

    //IP头部拷贝
    uint8_t ip_header_temp[UDP_PESO_LEN];
    memcpy(ip_header_temp,buf->data,UDP_PESO_LEN);

    //填写UDP伪头部的12字节字段
    udp_peso_hdr_t peso_hdr;
    memcpy(peso_hdr.src_ip,src_ip,NET_IP_LEN);
    memcpy(peso_hdr.dest_ip,dest_ip,NET_IP_LEN);
    peso_hdr.placeholder = 0;
    peso_hdr.protocol = NET_PROTOCOL_UDP;
    peso_hdr.total_len = udp_hdr.total_len;
    memcpy(buf->data,&peso_hdr,sizeof(udp_peso_hdr_t));
    buf->data[10] = peso_hdr.total_len >> 8;
    buf->data[11] = peso_hdr.total_len & 0xff;
    
    //计算UDP校验和
    int peso_len = peso_hdr.total_len + UDP_PESO_LEN;
    uint16_t cksum;
    //在奇数长度的数据报尾部追加一个值为0的填充（虚）字节
    if(peso_len % 2 == 1){
        uint8_t temp = buf->data[peso_len];
        buf->data[peso_len] = 0;
        peso_len++;
        cksum = checksum16((uint16_t*) buf->data, peso_len/2);
        buf->data[peso_len-1] = temp;
    }
    else{
        cksum = checksum16((uint16_t*) buf->data, peso_len/2);
    }
    
    //暂存的IP头部拷贝回来
    memcpy(buf->data,ip_header_temp,12);
    buf_remove_header(buf,UDP_PESO_LEN);
    return cksum;
}

/**
 * @brief 处理一个收到的udp数据包
 *        你首先需要检查UDP报头长度
 *        接着计算checksum，步骤如下：
 *          （1）先将UDP首部的checksum缓存起来
 *          （2）再将UDP首都的checksum字段清零
 *          （3）调用udp_checksum()计算UDP校验和
 *          （4）比较计算后的校验和与之前缓存的checksum进行比较，如不相等，则不处理该数据报。
 *       然后，根据该数据报目的端口号查找udp_table，查看是否有对应的处理函数（回调函数）
 *       
 *       如果没有找到，则调用buf_add_header()函数增加IP数据报头部(想一想，此处为什么要增加IP头部？？)
 *       然后调用icmp_unreachable()函数发送一个端口不可达的ICMP差错报文。
 * 
 *       如果能找到，则去掉UDP报头，调用处理函数（回调函数）来做相应处理。
 * 
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    udp_hdr.src_port = (buf->data[0]<<8) + buf->data[1];  // 源端口
    udp_hdr.dest_port = (buf->data[2]<<8) + buf->data[3]; // 目标端口
    udp_hdr.total_len = (buf->data[4]<<8) + buf->data[5]; // 整个数据包的长度
    udp_hdr.checksum = (buf->data[6]<<8) + buf->data[7];  // 校验和

    buf->len = udp_hdr.total_len;
    //检查UDP报头长度
    if(udp_hdr.total_len < 8) return;
    //计算checksum
    uint8_t if_ip[] = DRIVER_IF_IP;
    if(udp_checksum(buf,src_ip,if_ip)!=0) return;
    //根据该数据报目的端口号查找udp_table
    int index = udp_lookup(udp_hdr.dest_port);
    if(index != -1){
        buf_remove_header(buf,8);
        //回调函数
        udp_table[index].handler(&udp_table[index], src_ip, udp_hdr.src_port, buf);
    }
    else
    {
        buf_add_header(buf,20);
        buf->data[0] = IP_VERSION_4*16 + 5;
        buf->data[1] = 0;
        buf->data[2] = (buf->len & 0xff00)>>8; 
        buf->data[3] = buf->len & 0x00ff;
        buf->data[4] = 0;   buf->data[5] = 0;
        buf->data[6] = 0;   buf->data[7] = 0;
        buf->data[8] = 64;  buf->data[9] = NET_PROTOCOL_UDP;
        buf->data[10] = 0;  buf->data[11] = 0;
        uint8_t if_ip[] = DRIVER_IF_IP;
        memcpy(&buf->data[12] ,if_ip,NET_IP_LEN);
        memcpy(&buf->data[16] ,src_ip,NET_IP_LEN);
        uint16_t cksum = checksum16((uint16_t*)buf->data,buf->len/2);
        buf->data[10] = (cksum & 0xff00)>>8;
        buf->data[11] = cksum & 0x00ff;

        icmp_unreachable(buf,if_ip,ICMP_CODE_PORT_UNREACH);
    }

}

/**
 * @brief 处理一个要发送的数据包
 *        你首先需要调用buf_add_header()函数增加UDP头部长度空间
 *        填充UDP首部字段
 *        调用udp_checksum()函数计算UDP校验和
 *        将封装的UDP数据报发送到IP层。    
 * 
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dest_ip 目的ip地址
 * @param dest_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dest_ip, uint16_t dest_port)
{   
    // 增加UDP报头
    buf_add_header(buf,8);

    //源端口号
    buf->data[0] = src_port >> 8;
    buf->data[1] = src_port & 0xff;
    //目的端口号
    buf->data[2] = dest_port >> 8;
    buf->data[3] = dest_port & 0xff;
    //长度
    buf->data[4] = buf->len >> 8;
    buf->data[5] = buf->len & 0xff;
    //校验和
    buf->data[6] = 0;buf->data[7] = 0;

    // //调用 udp_checksum 函数计算校验和。
    // uint8_t if_ip[] = DRIVER_IF_IP;
    // uint16_t cksum = udp_checksum(buf,if_ip,dest_ip);
    // buf->data[6] = cksum >> 8;
    // buf->data[7] = cksum & 0xff;

    //调用 ip_out 函数发送 UDP 数据报。
    ip_out(buf,dest_ip,NET_PROTOCOL_UDP);

}

/**
 * @brief 初始化udp协议
 * 
 */
void udp_init()
{
    for (int i = 0; i < UDP_MAX_HANDLER; i++)
        udp_table[i].valid = 0;
}

/**
 * @brief 打开一个udp端口并注册处理程序
 * 
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    for (int i = 0; i < UDP_MAX_HANDLER; i++) //试图更新
        if (udp_table[i].port == port)
        {
            udp_table[i].handler = handler;
            udp_table[i].valid = 1;
            return 0;
        }

    for (int i = 0; i < UDP_MAX_HANDLER; i++) //试图插入
        if (udp_table[i].valid == 0)
        {
            udp_table[i].handler = handler;
            udp_table[i].port = port;
            udp_table[i].valid = 1;
            return 0;
        }
    return -1;
}

/**
 * @brief 关闭一个udp端口
 * 
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    for (int i = 0; i < UDP_MAX_HANDLER; i++)
        if (udp_table[i].port == port)
            udp_table[i].valid = 0;
}

/**
 * @brief 发送一个udp包
 * 
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dest_ip 目的ip地址
 * @param dest_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dest_ip, uint16_t dest_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dest_ip, dest_port);
}