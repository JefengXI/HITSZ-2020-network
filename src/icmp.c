#include "icmp.h"
#include "ip.h"
#include <string.h>
#include <stdio.h>

/**
 * @brief 处理一个收到的数据包
 *        你首先要检查ICMP报头长度是否小于icmp头部长度
 *        接着，查看该报文的ICMP类型是否为回显请求，
 *        如果是，则回送一个回显应答（ping应答），需要自行封装应答包。
 * 
 *        应答包封装如下：
 *        首先调用buf_init()函数初始化txbuf，然后封装报头和数据，
 *        数据部分可以拷贝来自接收到的回显请求报文中的数据。
 *        最后将封装好的ICMP报文发送到IP层。  
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    icmp_hdr_t icmp_hdr;
    icmp_hdr.type = buf->data[0];
    icmp_hdr.code = buf->data[1];
    icmp_hdr.checksum = (buf->data[2]<<8)+buf->data[3];
    icmp_hdr.id = (buf->data[4]<<8)+buf->data[5];
    icmp_hdr.seq = (buf->data[6]<<8)+buf->data[7];

    //对包括 ICMP 报文数据部分在内的整个 ICMP 数据报的校验和
    if(checksum16((uint16_t*) buf->data, buf->len/2)!=0) return;
    
    uint16_t static this_seq = 1;
    //查看该报文的ICMP类型是否为回显请求
    if(icmp_hdr.type==ICMP_TYPE_ECHO_REQUEST){
        buf_init(&txbuf,buf->len);
        memset(&txbuf.data[0],0,sizeof(uint8_t)*4);
        txbuf.data[4] = (icmp_hdr.seq) >> 8;
        txbuf.data[5] = icmp_hdr.seq & 0xff;
        txbuf.data[6] = (this_seq) >> 8;
        txbuf.data[7] = this_seq & 0xff;
        memcpy(&txbuf.data[8],&buf->data[8],buf->len-8);
        
        uint16_t cksum = checksum16((uint16_t*) txbuf.data, buf->len/2);
        txbuf.data[2] = (cksum&0xff00) >> 8;
        txbuf.data[3] = cksum & 0xff;

        this_seq++;
        ip_out(&txbuf,src_ip,NET_PROTOCOL_ICMP);
    }
    

    
}

/**
 * @brief 发送icmp不可达
 *        你需要首先调用buf_init初始化buf，长度为ICMP头部 + IP头部 + 原始IP数据报中的前8字节 
 *        填写ICMP报头首部，类型值为目的不可达
 *        填写校验和
 *        将封装好的ICMP数据报发送到IP层。
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{   
    //ICMP 差错报文
    int icmp_len = 36;
    buf_init(&txbuf,icmp_len);
    txbuf.data[0] = 3; txbuf.data[1] = code;
    memset(&txbuf.data[2],0,sizeof(uint8_t)*6);
    memcpy(&txbuf.data[8],recv_buf->data,28);

    uint16_t cksum = checksum16((uint16_t*) txbuf.data, icmp_len/2);
    txbuf.data[2] = (cksum&0xff00) >> 8;
    txbuf.data[3] = cksum & 0xff;

    ip_out(&txbuf,src_ip,NET_PROTOCOL_ICMP);
}