/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>

struct tcphdr 
{
	__be16	source;			//源端口(Source Port)
	__be16	dest;			//目的端口(Destination port)
	__be32	seq;			//序列号(Sequence Number)
	__be32	ack_seq;		//(Acknowledgment Number)
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,		
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,			//首部长度(Data Offset)
		res1:4,				//(Reserved)
		cwr:1,				
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window;
	__sum16	check;			//检验和(Checksum)
	__be16	urg_ptr;		//紧急指针(Urgent Pointer)
};

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union tcp_word_hdr 
{ 
	struct tcphdr hdr;
	__be32 		  words[5];
}; 

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

enum { 
	TCP_FLAG_CWR = __constant_htonl(0x00800000), 
	TCP_FLAG_ECE = __constant_htonl(0x00400000), 
	TCP_FLAG_URG = __constant_htonl(0x00200000), 
	TCP_FLAG_ACK = __constant_htonl(0x00100000), 
	TCP_FLAG_PSH = __constant_htonl(0x00080000), 
	TCP_FLAG_RST = __constant_htonl(0x00040000), 
	TCP_FLAG_SYN = __constant_htonl(0x00020000), 
	TCP_FLAG_FIN = __constant_htonl(0x00010000),
	TCP_RESERVED_BITS = __constant_htonl(0x0F000000),
	TCP_DATA_OFFSET = __constant_htonl(0xF0000000)
}; 

/* TCP socket options */
#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_MAXSEG		2	/* Limit MSS */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TCP_INFO		11	/* Information about this connection. */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */
#define TCP_CONGESTION		13	/* Congestion control algorithm */
#define TCP_MD5SIG		14	/* TCP MD5 Signature (RFC2385) */

#define TCPI_OPT_TIMESTAMPS	1
#define TCPI_OPT_SACK		2
#define TCPI_OPT_WSCALE		4
#define TCPI_OPT_ECN		8

enum tcp_ca_state
{
	//初始状态，也就是没有检测到任何拥塞的情况.
	//正常状态，执行slow start算法或者是congestion avoid算法，取决于拥塞窗口和ssthresh的大小
	TCP_CA_Open = 0,
#define TCPF_CA_Open	(1<<TCP_CA_Open)
	//
	//状态就是当第一次由于收到SACK或者重复的ack而检测到拥塞时，就进入这个状态
	//当检测到duplicate ack或者是SACK时，进入此状态。在此状态下拥塞窗口不调整，每收到一个数据包都触发一个新的数据包的发送。
	//此时，TCP会使用一些启发式方法判断是不是真的发生了包的丢失。
	//The TCP disorder state indicates that packets are getting reordered in the network or we may have just
	//recovered from the congestion state but are not yet completely undone. Before entering into the recovery 
	//state, we always first enter into the disorder state. The disorder state is an initial indication of congestion
	TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)

	//由于一些拥塞通知事件而导致拥塞窗口减小,然后就会进入这个状态。比如ECN，ICMP，本地设备拥塞
	//检测到由ECN，ICMP，或者本地设置引起的拥塞提示时，进入此状态。在此状态下，每收到2个ACK就把拥塞窗口-1，直到减为原来的一半
	//本状态说明发生某种拥塞，例如ICMP源抑制、本地设备拥塞，所以TCP发送方会放缓数据发送
	TCP_CA_CWR = 2,
#define TCPF_CA_CWR	(1<<TCP_CA_CWR)

	// 当CWND减小
	//当检测到3个重复的ACK时进入此状态，一般由Disorder状态进入。立即重传第一个未确认的数据包，每收到2个ACK就把拥塞窗口-1
	//直到见到ssthresh（此值在进入Recovery状态时设置为拥塞窗口的一半）。TCP停留在此状态直到刚进入此状态时所有驻留网络的数据包都得到确认，然后
	//返回到open状态

	//本状态代表发送方正在进行快速重传丢失的数据包。
	TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)

	//超时或者SACK被拒绝，此时表示数据包丢失，因此进入这个状态
	//当RTO定时器超时时，进入此状态。所有驻留于网络的数据包都标记为Lost，拥塞窗口设置为1，启用slow start算法
	//当进入此状态时所有驻留于网络的数据包得到确认后，返回到Open状态

	//如果发生RTO，或者接收到的ACK与发送方记录的SACK信息不同步，就会进入这个状态。
	TCP_CA_Loss = 4
#define TCPF_CA_Loss	(1<<TCP_CA_Loss)
};

struct tcp_info
{
	__u8	tcpi_state;
	__u8	tcpi_ca_state;
	__u8	tcpi_retransmits;
	__u8	tcpi_probes;
	__u8	tcpi_backoff;
	__u8	tcpi_options;
	__u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

	__u32	tcpi_rto;
	__u32	tcpi_ato;
	__u32	tcpi_snd_mss;
	__u32	tcpi_rcv_mss;

	__u32	tcpi_unacked;
	__u32	tcpi_sacked;
	__u32	tcpi_lost;
	__u32	tcpi_retrans;
	__u32	tcpi_fackets;

	/* Times. */
	__u32	tcpi_last_data_sent;
	__u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
	__u32	tcpi_last_data_recv;
	__u32	tcpi_last_ack_recv;

	/* Metrics. */
	__u32	tcpi_pmtu;
	__u32	tcpi_rcv_ssthresh;
	__u32	tcpi_rtt;
	__u32	tcpi_rttvar;
	__u32	tcpi_snd_ssthresh;
	__u32	tcpi_snd_cwnd;
	__u32	tcpi_advmss;
	__u32	tcpi_reordering;

	__u32	tcpi_rcv_rtt;
	__u32	tcpi_rcv_space;

	__u32	tcpi_total_retrans;
};

/* for TCP_MD5SIG socket option */
#define TCP_MD5SIG_MAXKEYLEN	80

struct tcp_md5sig {
	struct __kernel_sockaddr_storage tcpm_addr;	/* address associated */
	__u16	__tcpm_pad1;				/* zero */
	__u16	tcpm_keylen;				/* key length */
	__u32	__tcpm_pad2;				/* zero */
	__u8	tcpm_key[TCP_MD5SIG_MAXKEYLEN];		/* key (binary) */
};

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include <linux/dmaengine.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}

static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
	return tcp_hdr(skb)->doff * 4;
}

static inline unsigned int tcp_optlen(const struct sk_buff *skb)
{
	return (tcp_hdr(skb)->doff - 5) * 4;
}

/* This defines a selective acknowledgement block. */
struct tcp_sack_block_wire 
{
	__be32	start_seq;
	__be32	end_seq;
};

struct tcp_sack_block
{
	u32	start_seq;	//起始序号
	u32	end_seq;	//结束序号
};

struct tcp_options_received 
{
	/*	PAWS/RTTM data	*/
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
	u32		ts_recent;	/* Time stamp to echo next		*/
	u32		rcv_tsval;	/* Time stamp value             	*/
	//the echoed timestamp from the receiver
	u32		rcv_tsecr;	/* Time stamp echo reply        	*/
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
			tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
			//下一个发送段是否存在D-SACK
			dsack : 1,	/* D-SACK is scheduled			*/
			wscale_ok : 1,	/* Wscale seen on SYN packet		*/
			//接收方是否支持SACK
			sack_ok : 4,	/* SACK seen on SYN packet		*/
			//Window scaling received from sender
			//对端接收窗口扩大因子
			snd_wscale : 4,	
			//Window scaling to send to receiver
			//本端接收窗口扩大因子
			rcv_wscale : 4;	
	/*	SACKs data	*/
	u8		eff_sacks;	/* Size of SACK array to send with next packet */
	//下一个发送段中SACK块数
	u8		num_sacks;	/* Number of SACK blocks		*/
	//mss requested by user in ioctl
	//用户通过TCP_MAXSEG选项设置的MSS上限，用于决定本端和对端的接收MSS上限
	u16		user_mss;  	
	//对端的能接收的MSS上限，连接建立阶段协商值min(tp->rx_opt.user_mss, 对端在建立连接时通告的MSS)
	u16		mss_clamp;	
};

struct tcp_request_sock
{
	struct inet_request_sock 	req;
#ifdef CONFIG_TCP_MD5SIG
	/* Only used by TCP MD5 Signature so far. */
	struct tcp_request_sock_ops	*af_specific;
#endif
	u32			 	rcv_isn;
	u32			 	snt_isn;
};

static inline struct tcp_request_sock *tcp_rsk(const struct request_sock *req)
{
	return (struct tcp_request_sock *)req;
}

//tcp_sock结构是TCP协议的控制块，它在inet_connection_sock结构的基础上
//扩展了滑动窗口协议、拥塞控制算法等一些TCP专有属性
struct tcp_sock 
{
	/* inet_connection_sock has to be the first member of tcp_sock */
	struct inet_connection_sock	inet_conn;
	//TCP首部长度，包括TCP选项
	u16	tcp_header_len;	/* Bytes of tcp header to send		*/
	u16	xmit_size_goal;	/* Goal for segmenting output packets	*/

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */

 	//期待接收的下一个TCP段的起始序列号
 	u32	rcv_nxt;	
	//Head of yet unread data
	//应用程序还未读取的数据的起始序列号
	u32	copied_seq;	

	//最早接收但未确认的段的序号，即当前接收窗口的左端。
	//在发送ACK时，由rcv_nxt更新，因此rcv_wup的更新通常比rcv_nxt滞后一些
	u32	rcv_wup;
	
	//将要发送的下一个TCP段的起始序列号
 	u32	snd_nxt;	

	//发送窗口中的发送但未被确认的第一个字节的序列号
 	u32	snd_una;	
	//最近发送的小包(小于MSS的段)的最后一个字节的序号，在成功发送段后，
	//如果报文小于MSS，即更新该字段，主要用来判断是否启用Nagle算法
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
	//最近一次接收到ack的时间戳，主要用于keepalive
	u32	rcv_tstamp;
	//timestamp of last sent data packet (for restart window)
	//最近一次发送数据包的时间戳，主要用于拥塞窗口的设置
	u32	lsndtime;	

	/* Data for direct copy to user */
	//用来控制复制数据到用户进程的控制块
	struct
	{
		//prequeue对列
		//
		struct sk_buff_head	prequeue;
		///表示当前所处的进程，其实也就是skb的接受者
		struct task_struct	*task;
		///数据区
		struct iovec		*iov;
		//prequeue队列当前消耗的内存大小
		int			memory;
		///表示用户所请求的长度(要注意这个值是可变的，随着拷贝给用户的数据而减少)
		int			len;
#ifdef CONFIG_NET_DMA
		/* members for async copy */
		struct dma_chan		*dma_chan;
		int			wakeup;
		struct dma_pinned_list	*pinned_list;
		dma_cookie_t		dma_cookie;
#endif
	} ucopy;
	
	//记录更新发送窗口的那个ACK段序号，用于下一次判断是否需要更新窗口。
	//如果后续收到的ACK段的序号大于snd_wl1，则说明需更新窗口，否则无需更新。
	u32	snd_wl1;	
	///接收方(对端)通告的窗口大小(经过窗口扩大选项处理后的值)，即发送方(本端)发送窗口大小
	u32	snd_wnd;	
	//接收方(对端)通告过的最大接收窗口值
	u32	max_window;	
	//Cached effective mss, not including SACKS
	//发送方(本端)当前有效的发送MSS。
	//显然不能超过接收方(对端)接收的上限，tp->mss_cache <= tp->rx_opt.mss_clamp。参见SOL_TCP选项
	u32	mss_cache;	
	//Maximal window to advertise
	//接收窗口的最大值，这个值也会动态调整
	u32	window_clamp;
	//当前接收窗口大小的阈值
	//On reception of data segment from the sender, this value is recalculated based on the size of the
	//segment, and later on this value is used as upper limit on the receive window to be advertised.
	u32	rcv_ssthresh;	
	
	//当超时重传发生时，在启用F-RTO情况下，用来保存待发送的下一个TCP段的序号snd_nxt。
	//在tcp_process_frto()中处理F-RTO时使用。
	u32	frto_highmark;	/* snd_nxt when RTO occurred */
	
	//在不支持SACK时，为由于连接接受到重复确认而进入快速恢复阶段的重复确认数阈值。
	//在支持SACK时，在没有确定丢失包的情况下，是TCP流中可以重排序的数据段数
	//由相关路由缓存项中的reordering度量值或系统参数sysctl_tcp_reordering进行初始化，
	//更新时会同时更新到目的路由缓存项的reordering度量值中。
	u8	reordering;	/* Packet reordering metric.		*/
	//在传送超时后，记录在启用F-RTO算法时接收到ACK段的数目。传送超时后，如果启用了F-RTO算法，则进入F-RTO处理阶段，
	//在此阶段，如果连续接收到3个对新数据确认ACK段，则恢复到正常模式下。非零时，也表示在F-RTO处理阶段
	u8	frto_counter;	/* Number of new acks after RTO */
	u8	nonagle;	/* Disable Nagle algorithm?             */
	u8	keepalive_probes; /* num of allowed keep alive probes	*/

/* RTT measurement */
	//平滑的RTT，为了避免浮点运算，是将其放大8倍后存储的
	u32	srtt;		/* smoothed round trip time << 3	*/

	//RTT平均偏差，由RTT与RTT均值偏差绝对值加权平均而得到
	//其值越大说明RTT抖动得越厉害
	u32	mdev;	
	
	//跟踪每次发送窗口内段被全部确认过程中，RTT平均偏差的最大值，描述RTT抖动的最大范围
	u32	mdev_max;	/* maximal mdev for the last rtt period	*/

	//平滑的RTT平均偏差，由mdev计算得到，用来计算RTO
	u32	rttvar;		/* smoothed mdev_max			*/
	
	//记录snd_una，用来在计算RTO时比较snd_una是否被更新了，如果被snd_una更新，则需要同时更新rttvar
	u32	rtt_seq;	/* sequence number to update rttvar	*/
	
	//Packets which are "in flight"
	//已发送但还没被确认的TCP段的数目(即snd_nxt - snd_una)
	//该值是动态的，当有新的段发出或有新的确认收到都会增加或减小该值
	u32	packets_out;	
	
	//重传但还没被确认的TCP段数目
	//takes care of the retransmitted segments marked as lost. 
	//This will be helpful in detecting partial ACKing in the congestion state. 
	u32	retrans_out;	
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
	struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	//拥塞控制时慢启动的阈值
 	//如果snd_cwnd < snd_ssthresh，则处在慢启动阶段
 	u32	snd_ssthresh;	

	//当前拥塞窗口大小
 	u32	snd_cwnd;		
	//Linear increase counter		
	//A counter used to slow down the rate of increase once we exceed slow start threshold.
	//表示在当前的拥塞控制窗口中已经发送的数据段的个数

	//自从上次调整拥塞窗口到目前为止接收到的总ACK段数。
	//如果该字段值为0，则说明已经调整了拥塞窗口，且到目前为止还没有接收到ACK段。
	//调整拥塞窗口之后，每接收到一个ACK段就会使snd_cwnd_cnt增1
	u32	snd_cwnd_cnt;	
	
	//允许的最大拥塞窗口值。初始值为65535，之后在接收SYN和ACK段时，会根据条件确定是否从路由配置项读取信息更新该字段，
	//最后在TCP连接复位前，将更新后的值根据某种算法计算后再更新回相应的路由配置项中，便于连接使用
	u32	snd_cwnd_clamp; 
	
	//Used as a highwater mark for how much of the congestion window is in use. 
	//It is used to adjust snd_cwnd down when the link is limited by the application rather than the network.
	//当应用程序限制时，记录当前从发送队列发出而未得到确认的段数，用于在检验拥塞窗口时调节拥塞窗口，避免拥塞窗口失效
	u32	snd_cwnd_used;
	
	//Timestamp for when congestion window last validated. 
	//记录最后一次调整拥塞窗口的时间
	
	//记录最近一次检验拥塞窗口的时间。
	//在拥塞期间，接收到ACK后会进行拥塞窗口的检验。
	//在非拥塞期间，为了防止由于应用程序限制而造成拥塞窗口失效，因此在成功发送段后，如果有必要也会检验拥塞窗口
	u32	snd_cwnd_stamp;

	//乱序缓存队列，用来暂存接收到的乱序的TCP段
	struct sk_buff_head	out_of_order_queue;

	//当前的接收窗口(通告给对端的窗口)大小
 	u32	rcv_wnd;
	//已经加入到发送队列中的最后一个字节的序号
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */

/*	SACKs data	*/
	//存储用于回复对端SACK的信息
	//duplicate_sack存储D-SACK信息，selective_acks存储SACK信息，
	//在回复SACK时会从中取出D-SACK和SACK信息，而在处理接收到乱序的段时，会向这个两个字段中填入相应的信息
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	//存储接收到的SACK选项的信息
	struct tcp_sack_block_wire recv_sack_cache[4];
	///被SACK确认的所有报文段中最大的起始序列号
	u32	highest_sack;	/* Start seq of globally highest revd SACK(validity guaranteed only if sacked_out > 0) */

	/* from STCP, retrans queue hinting */
	//一般在拥塞状态没有撤销或没有进入Loss状态时，在重传队列中，缓存上一次标记记分牌未丢失的最后一个段，
	//主要为了加速对重传队列的标记操作。
	struct sk_buff* lost_skb_hint;
	
	//一般在拥塞状态没有撤销或没有进入Loss状态时，在重传队列中，记录上一次标记记分牌未丢失的最后一个SKB，
	//主要为了加速对重传队列的标记操作。
	struct sk_buff *scoreboard_skb_hint;

	//用于记录上次重传的位置。
	//retransmit_skb_hint位置之前的段经过了重传，当认为重传的段也已经丢失，则将其设置为NULL，这样重传
	//又从sk_write_queue开始，即使该段并未真正丢失。
	//重新排序也正是这个意思，这与系统参数sysctl_tcp_reordering也有着密切关系
	struct sk_buff *retransmit_skb_hint;

	//当支持SACK或FACK时，在重传处于SACK块中的空隙中的段时，用于记录由于满足其他条件而未能重传的位置，下次可以从此位置继续处理。
	//如果重传了，则下次从重传队列队首重新处理
	struct sk_buff *forward_skb_hint;

	//SACK选项处理的快速路径中使用，上次第一个SACK块的结束处
	//fastpath_skb_hint记录上一次处理SACK选项的最高序号段的SKB，即下一次处理SACK选项的开始处
	//而fastpath_cnt_hint记录上一次计算得到的fackets_out，
	//目的是为了在拥塞状态没有发生变化或接收到SACK没有发送变化等情况下，加速对fackets_out、sacked_out等的计算
	struct sk_buff *fastpath_skb_hint;

	/* 快速路径中使用，上次记录的fack_count，现在继续累加 */
	int     fastpath_cnt_hint;	/* Lags behind by current skb's pcount
					 * compared to respective fackets_out */
	//lost_skb_hint的个数xxx
	int     lost_cnt_hint;
	//retransmit_skb_hint的个数xxx
	int     retransmit_cnt_hint;

	u32	lost_retrans_low;	/* Sent seq after any rxmit (lowest) */
	//Advertised MSS
	//本端能接收的MSS上限, 建立连接时用来通告对端
	//此值由路由缓存项中MSS度量值(RTAX_ADVMSS)进行初始化，
	//而路由缓存项中MSS度量值则直接取自网络设备接口的MTU减去IP首部及TCP首部的长度，一般是1460。参见rt_set_nexthop()。
	u16	advmss;		
	
	//在启用FRTO算法的情况下，路径MTU探测成功，进入拥塞控制Disorder、Recovery、Loss状态时保存的ssthresh值。
	//主要用来在拥塞窗口撤销时，恢复拥塞控制的慢启动阈值。
	//当prior_ssthresh被设置为0时，	avoid increasing the congestion window to a very high value when undo from 
	//a non-open state, (tcp_undo_cwr())
	u16	prior_ssthresh; /* ssthresh saved at recovery start	*/
	
	//Packets lost by network. TCP has no explicit "loss notification" feedback from network (for now).
	//It means that this number can be only _guessed_. Actually, it is the heuristics to predict lossage that
	//distinguishes different algorithms.
	//an estimation of the number of segments lost in the network.
	//网络中丢失的数据包的计数，是一个估计值，取决于具体实现
	//tp->lost_out is incremented in tcp_mark_head_lost() even if we are in a disorder state or an open state.
	u32	lost_out;	
	//Packets, which arrived to receiver out of order and hence not ACKed. With SACKs this number is simply
	//amount of SACKed data. Even without SACKs it is easy to give pretty reliable estimate of this number,
	//counting duplicate ACKs.
	//启用SACK时，通过SACK的TCP选项标识确认的已接收到段的数量
	//不启用SACK时，标识接收到重复确认的次数。此值在接收到确认新数据的段时被清除
	u32	sacked_out;	

	//记录snd_una与SACK选项中目前接收方收到的段中最高序号段之间的段数。
	//FACK算法用SACK选项来计算丢失在网络上的段数。例如:
	//lost_out = fackets_out - sacked_out
	//left_out = fackets_out
	u32	fackets_out;	/* FACK'd packets			*/

	//记录发生拥塞时的最大的发送序号(snd_nxt)， 标识重传队列的尾部
	//tp->high_seq is set to the highest sequence number that has been
	//transmitted at that point of time when we enter loss or recovery (cwr) state.
	u32	high_seq;	

	//在主动连接时，记录第一个SYN段的发送时间，用来检测ACK序号是否回绕
	//在数据传输阶段，当发送超时重传时，记录重传阶段过程第一个重传段的发送时间，用来判断是否可以进行拥塞撤销
	// timestamp of the first retransmission, used to detect false retransmissions
	//显然retrans_out为0时, retrans_stamp也要为0
	u32	retrans_stamp;	
	//在使用F-RTO算法进行发送超时处理，或进入Recovery进行重传，或进入Loss开始慢启动时，
	//记录当时snd_una，标记重传的起始点。它是检测是否可以进行拥塞撤销的条件之一，
	//一般在完成拥塞撤销操作或进入拥塞控制Loss状态状态后清零。
	///表示发生重传时的snd_una
	///超时重传或FRTO时记录的snd_una
	//set to tp->snd_una when we enter the recovery phase and retransmit data,
	//this is set to unACKed sequence number (tp->snd_una) when we enter the congestion state. 
	//0 means that we don't want to undo from the congestion state (tcp_may_undo())
	u32	undo_marker;	/* tracking retrans started here. */
	///记录重传数据包的个数，如果undo_retrans降到0，
    ///就说明之前的重传都是不必要的，进行拥塞调整撤销。

	//在恢复拥塞控制之前可进行撤销的重传段数。在进入FRTO算法或拥塞控制状态Loss时清零，
	//在重传时计数，是检测是否可以进行拥塞撤销的条件之一。
	//helps in detecting false retransmits in recovery/loss state
	int	undo_retrans;	/* number of undoable retransmissions. */
	u32	urg_seq;	/* Seq of received urgent pointer */
	u16	urg_data;	/* Saved octet of OOB data and control flags */
	u8	urg_mode;	/* In urgent mode		*/
	//显示拥塞通知状态位: TCP_ECN_OK / TCP_ECN_QUEUE_CWR / TCP_ECN_DEMAND_CWR
	u8	ecn_flags;	
	u32	snd_up;		/* Urgent pointer		*/

	//在整个连接中总重传次数
	u32	total_retrans;	
	//在启用sysctl_tcp_abc(Appropriate Byte Counting)之后，在拥塞避免阶段，保存已确认的字节数，参见RFC3465
	u32	bytes_acked;	

	unsigned int		keepalive_time;	  /* time before keep alive takes place */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */
	int			linger2;

	unsigned long last_synq_overflow; 

	u32	tso_deferred;

/* Receiver side RTT estimation */
	struct {
		u32	rtt;
		u32	seq;
		u32	time;
	} rcv_rtt_est;

/* Receiver queue space */
	struct 
	{
		int	space;
		u32	seq;
		u32	time;
	} rcvq_space;

/* TCP-specific MTU probe information. */
	struct 
	{
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;

#ifdef CONFIG_TCP_MD5SIG
/* TCP AF-Specific parts; only used by MD5 Signature support so far */
	struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signagure Option information */
	struct tcp_md5sig_info	*md5sig_info;
#endif
};

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

struct tcp_timewait_sock {
	struct inet_timewait_sock tw_sk;
	u32			  tw_rcv_nxt;
	u32			  tw_snd_nxt;
	u32			  tw_rcv_wnd;
	u32			  tw_ts_recent;
	long			  tw_ts_recent_stamp;
#ifdef CONFIG_TCP_MD5SIG
	u16			  tw_md5_keylen;
	u8			  tw_md5_key[TCP_MD5SIG_MAXKEYLEN];
#endif
};

static inline struct tcp_timewait_sock *tcp_twsk(const struct sock *sk)
{
	return (struct tcp_timewait_sock *)sk;
}

#endif

#endif	/* _LINUX_TCP_H */
