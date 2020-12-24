#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include <string.h>


/**
 * @brief 处理一个收到的数据包
 *        你首先需要做报头检查，检查项包括：版本号、总长度、首部长度等。
 * 
 *        接着，计算头部校验和，注意：需要先把头部校验和字段缓存起来，再将校验和字段清零，
 *        调用checksum16()函数计算头部检验和，比较计算的结果与之前缓存的校验和是否一致，
 *        如果不一致，则不处理该数据报。
 * 
 *        检查收到的数据包的目的IP地址是否为本机的IP地址，只处理目的IP为本机的数据报。
 * 
 *        检查IP报头的协议字段：
 *        如果是ICMP协议，则去掉IP头部，发送给ICMP协议层处理
 *        如果是UDP协议，则去掉IP头部，发送给UDP协议层处理
 *        如果是本实验中不支持的其他协议，则需要调用icmp_unreachable()函数回送一个ICMP协议不可达的报文。
 *          
 * @param buf 要处理的包
 */
void ip_in(buf_t *buf)
{   
    //set ip_hdr
    ip_hdr_t ip_hdr;
    ip_hdr.version = (buf->data[0]&0xf0)>>4;
    ip_hdr.hdr_len = (buf->data[0]&0x0f);
    //check ip_hdr
    if( (ip_hdr.version != IP_VERSION_4) && (ip_hdr.hdr_len < 5 )) return;
    
    ip_hdr.tos = buf->data[1];
    ip_hdr.total_len = (buf->data[2]<<8) + buf->data[3];
    ip_hdr.id = (buf->data[4]<<8) + buf->data[5];
    ip_hdr.flags_fragment = (buf->data[6]<<8) + buf->data[7];
    ip_hdr.ttl = buf->data[8];
    ip_hdr.protocol = buf->data[9];
    ip_hdr.hdr_checksum = (buf->data[10]<<8) +buf->data[11];
    memcpy(ip_hdr.src_ip ,&buf->data[12],NET_IP_LEN);
    memcpy(ip_hdr.dest_ip ,&buf->data[16],NET_IP_LEN);

    //运算单位是双字节
    if(checksum16((uint16_t*) buf->data, ip_hdr.hdr_len*IP_HDR_LEN_PER_BYTE/2)!=0) return;
    //check DEST IP
    uint8_t if_ip[] = DRIVER_IF_IP;
    if(memcmp(ip_hdr.dest_ip,if_ip,NET_IP_LEN)!=0) return;

    switch (ip_hdr.protocol)
    {
    case NET_PROTOCOL_ICMP:
        buf_remove_header(buf, ip_hdr.hdr_len*IP_HDR_LEN_PER_BYTE);
        icmp_in(buf,ip_hdr.src_ip);
        break;

    case NET_PROTOCOL_UDP:
        buf_remove_header(buf, ip_hdr.hdr_len*IP_HDR_LEN_PER_BYTE);
        udp_in(buf,ip_hdr.src_ip);
        break;
    
    default:
        icmp_unreachable(buf,ip_hdr.src_ip,ICMP_CODE_PROTOCOL_UNREACH);
        break;
    }

}

/**
 * @brief 处理一个要发送的ip分片
 *        你需要调用buf_add_header增加IP数据报头部缓存空间。
 *        填写IP数据报头部字段。
 *        将checksum字段填0，再调用checksum16()函数计算校验和，并将计算后的结果填写到checksum字段中。
 *        将封装后的IP数据报发送到arp层。
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{   
    buf_add_header(buf,20);

    buf->data[0] = IP_VERSION_4*16 + 5;
    buf->data[1] = 0;
    buf->data[2] = (buf->len & 0xff00)>>8; 
    buf->data[3] = buf->len & 0x00ff;

    buf->data[4] = (id & 0xff00)>>8;
    buf->data[5] = id & 0x00ff;
    buf->data[6] = mf + ((offset & 0x1f00)>>8);
    buf->data[7] = (offset & 0x00ff);

    buf->data[8] = 64;
    buf->data[9] = protocol;
    buf->data[10] = 0;
    buf->data[11] = 0;

    uint8_t if_ip[] = DRIVER_IF_IP;
    memcpy(&buf->data[12] ,if_ip,NET_IP_LEN);
    memcpy(&buf->data[16] ,ip,NET_IP_LEN);

    uint16_t cksum = checksum16((uint16_t*)buf->data,10);
    buf->data[10] = (cksum & 0xff00)>>8;
    buf->data[11] = cksum & 0x00ff;

    arp_out(buf,ip,NET_PROTOCOL_IP);

}

/**
 * @brief 处理一个要发送的ip数据包
 *        你首先需要检查需要发送的IP数据报是否大于以太网帧的最大包长（1500字节 - 以太网报头长度）。
 *        
 *        如果超过，则需要分片发送。 
 *        分片步骤：
 *        （1）调用buf_init()函数初始化buf，长度为以太网帧的最大包长（1500字节 - 以太网报头长度）
 *        （2）将数据报截断，每个截断后的包长度 = 以太网帧的最大包长，调用ip_fragment_out()函数发送出去
 *        （3）如果截断后最后的一个分片小于或等于以太网帧的最大包长，
 *             调用buf_init()函数初始化buf，长度为该分片大小，再调用ip_fragment_out()函数发送出去
 *             注意：id为IP数据报的分片标识，从0开始编号，每增加一个分片，自加1。最后一个分片的MF = 0
 *    
 *        如果没有超过以太网帧的最大包长，则直接调用调用ip_fragment_out()函数发送出去。
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{   
    // TODO 
    int id = 0;
    int max_len = ETHERNET_MTU - IP_HDR_LEN_PER_BYTE*5;
    // amount of slices
    int slices = buf->len/max_len + 1;
    if(slices > 1){
        for(int i=0; i < slices-1;i++){
            int offset = i*max_len;
            buf_t slice_buf;
            buf_init(&slice_buf,max_len);
            memcpy(slice_buf.data, &buf->data[offset], max_len);
            ip_fragment_out(&slice_buf, ip, protocol, id, offset/IP_HDR_OFFSET_PER_BYTE, IP_MORE_FRAGMENT);
        }
        int offset = (slices-1)*max_len,
            remain_len = buf->len - offset;
        buf_t slice_buf;
        buf_init(&slice_buf, remain_len);
        memcpy(slice_buf.data, &buf->data[offset], remain_len);
        ip_fragment_out(&slice_buf, ip, protocol, id, offset/IP_HDR_OFFSET_PER_BYTE, 0);
    }
    else{
        ip_fragment_out(buf, ip, protocol, id, 0, 0);
    }
    id += 1;
}
