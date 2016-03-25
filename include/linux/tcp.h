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
	__be16	source;			//Դ�˿�(Source Port)
	__be16	dest;			//Ŀ�Ķ˿�(Destination port)
	__be32	seq;			//���к�(Sequence Number)
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
	__u16	doff:4,			//�ײ�����(Data Offset)
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
	__sum16	check;			//�����(Checksum)
	__be16	urg_ptr;		//����ָ��(Urgent Pointer)
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
	//��ʼ״̬��Ҳ����û�м�⵽�κ�ӵ�������.
	//����״̬��ִ��slow start�㷨������congestion avoid�㷨��ȡ����ӵ�����ں�ssthresh�Ĵ�С
	TCP_CA_Open = 0,
#define TCPF_CA_Open	(1<<TCP_CA_Open)
	//
	//״̬���ǵ���һ�������յ�SACK�����ظ���ack����⵽ӵ��ʱ���ͽ������״̬
	//����⵽duplicate ack������SACKʱ�������״̬���ڴ�״̬��ӵ�����ڲ�������ÿ�յ�һ�����ݰ�������һ���µ����ݰ��ķ��͡�
	//��ʱ��TCP��ʹ��һЩ����ʽ�����ж��ǲ�����ķ����˰��Ķ�ʧ��
	//The TCP disorder state indicates that packets are getting reordered in the network or we may have just
	//recovered from the congestion state but are not yet completely undone. Before entering into the recovery 
	//state, we always first enter into the disorder state. The disorder state is an initial indication of congestion
	TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)

	//����һЩӵ��֪ͨ�¼�������ӵ�����ڼ�С,Ȼ��ͻ�������״̬������ECN��ICMP�������豸ӵ��
	//��⵽��ECN��ICMP�����߱������������ӵ����ʾʱ�������״̬���ڴ�״̬�£�ÿ�յ�2��ACK�Ͱ�ӵ������-1��ֱ����Ϊԭ����һ��
	//��״̬˵������ĳ��ӵ��������ICMPԴ���ơ������豸ӵ��������TCP���ͷ���Ż����ݷ���
	TCP_CA_CWR = 2,
#define TCPF_CA_CWR	(1<<TCP_CA_CWR)

	// ��CWND��С
	//����⵽3���ظ���ACKʱ�����״̬��һ����Disorder״̬���롣�����ش���һ��δȷ�ϵ����ݰ���ÿ�յ�2��ACK�Ͱ�ӵ������-1
	//ֱ������ssthresh����ֵ�ڽ���Recovery״̬ʱ����Ϊӵ�����ڵ�һ�룩��TCPͣ���ڴ�״ֱ̬���ս����״̬ʱ����פ����������ݰ����õ�ȷ�ϣ�Ȼ��
	//���ص�open״̬

	//��״̬�����ͷ����ڽ��п����ش���ʧ�����ݰ���
	TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)

	//��ʱ����SACK���ܾ�����ʱ��ʾ���ݰ���ʧ����˽������״̬
	//��RTO��ʱ����ʱʱ�������״̬������פ������������ݰ������ΪLost��ӵ����������Ϊ1������slow start�㷨
	//�������״̬ʱ����פ������������ݰ��õ�ȷ�Ϻ󣬷��ص�Open״̬

	//�������RTO�����߽��յ���ACK�뷢�ͷ���¼��SACK��Ϣ��ͬ�����ͻ�������״̬��
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
	u32	start_seq;	//��ʼ���
	u32	end_seq;	//�������
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
			//��һ�����Ͷ��Ƿ����D-SACK
			dsack : 1,	/* D-SACK is scheduled			*/
			wscale_ok : 1,	/* Wscale seen on SYN packet		*/
			//���շ��Ƿ�֧��SACK
			sack_ok : 4,	/* SACK seen on SYN packet		*/
			//Window scaling received from sender
			//�Զ˽��մ�����������
			snd_wscale : 4,	
			//Window scaling to send to receiver
			//���˽��մ�����������
			rcv_wscale : 4;	
	/*	SACKs data	*/
	u8		eff_sacks;	/* Size of SACK array to send with next packet */
	//��һ�����Ͷ���SACK����
	u8		num_sacks;	/* Number of SACK blocks		*/
	//mss requested by user in ioctl
	//�û�ͨ��TCP_MAXSEGѡ�����õ�MSS���ޣ����ھ������˺ͶԶ˵Ľ���MSS����
	u16		user_mss;  	
	//�Զ˵��ܽ��յ�MSS���ޣ����ӽ����׶�Э��ֵmin(tp->rx_opt.user_mss, �Զ��ڽ�������ʱͨ���MSS)
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

//tcp_sock�ṹ��TCPЭ��Ŀ��ƿ飬����inet_connection_sock�ṹ�Ļ�����
//��չ�˻�������Э�顢ӵ�������㷨��һЩTCPר������
struct tcp_sock 
{
	/* inet_connection_sock has to be the first member of tcp_sock */
	struct inet_connection_sock	inet_conn;
	//TCP�ײ����ȣ�����TCPѡ��
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

 	//�ڴ����յ���һ��TCP�ε���ʼ���к�
 	u32	rcv_nxt;	
	//Head of yet unread data
	//Ӧ�ó���δ��ȡ�����ݵ���ʼ���к�
	u32	copied_seq;	

	//������յ�δȷ�ϵĶε���ţ�����ǰ���մ��ڵ���ˡ�
	//�ڷ���ACKʱ����rcv_nxt���£����rcv_wup�ĸ���ͨ����rcv_nxt�ͺ�һЩ
	u32	rcv_wup;
	
	//��Ҫ���͵���һ��TCP�ε���ʼ���к�
 	u32	snd_nxt;	

	//���ʹ����еķ��͵�δ��ȷ�ϵĵ�һ���ֽڵ����к�
 	u32	snd_una;	
	//������͵�С��(С��MSS�Ķ�)�����һ���ֽڵ���ţ��ڳɹ����Ͷκ�
	//�������С��MSS�������¸��ֶΣ���Ҫ�����ж��Ƿ�����Nagle�㷨
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
	//���һ�ν��յ�ack��ʱ�������Ҫ����keepalive
	u32	rcv_tstamp;
	//timestamp of last sent data packet (for restart window)
	//���һ�η������ݰ���ʱ�������Ҫ����ӵ�����ڵ�����
	u32	lsndtime;	

	/* Data for direct copy to user */
	//�������Ƹ������ݵ��û����̵Ŀ��ƿ�
	struct
	{
		//prequeue����
		//
		struct sk_buff_head	prequeue;
		///��ʾ��ǰ�����Ľ��̣���ʵҲ����skb�Ľ�����
		struct task_struct	*task;
		///������
		struct iovec		*iov;
		//prequeue���е�ǰ���ĵ��ڴ��С
		int			memory;
		///��ʾ�û�������ĳ���(Ҫע�����ֵ�ǿɱ�ģ����ſ������û������ݶ�����)
		int			len;
#ifdef CONFIG_NET_DMA
		/* members for async copy */
		struct dma_chan		*dma_chan;
		int			wakeup;
		struct dma_pinned_list	*pinned_list;
		dma_cookie_t		dma_cookie;
#endif
	} ucopy;
	
	//��¼���·��ʹ��ڵ��Ǹ�ACK����ţ�������һ���ж��Ƿ���Ҫ���´��ڡ�
	//��������յ���ACK�ε���Ŵ���snd_wl1����˵������´��ڣ�����������¡�
	u32	snd_wl1;	
	///���շ�(�Զ�)ͨ��Ĵ��ڴ�С(������������ѡ�����ֵ)�������ͷ�(����)���ʹ��ڴ�С
	u32	snd_wnd;	
	//���շ�(�Զ�)ͨ����������մ���ֵ
	u32	max_window;	
	//Cached effective mss, not including SACKS
	//���ͷ�(����)��ǰ��Ч�ķ���MSS��
	//��Ȼ���ܳ������շ�(�Զ�)���յ����ޣ�tp->mss_cache <= tp->rx_opt.mss_clamp���μ�SOL_TCPѡ��
	u32	mss_cache;	
	//Maximal window to advertise
	//���մ��ڵ����ֵ�����ֵҲ�ᶯ̬����
	u32	window_clamp;
	//��ǰ���մ��ڴ�С����ֵ
	//On reception of data segment from the sender, this value is recalculated based on the size of the
	//segment, and later on this value is used as upper limit on the receive window to be advertised.
	u32	rcv_ssthresh;	
	
	//����ʱ�ش�����ʱ��������F-RTO����£�������������͵���һ��TCP�ε����snd_nxt��
	//��tcp_process_frto()�д���F-RTOʱʹ�á�
	u32	frto_highmark;	/* snd_nxt when RTO occurred */
	
	//�ڲ�֧��SACKʱ��Ϊ�������ӽ��ܵ��ظ�ȷ�϶�������ٻָ��׶ε��ظ�ȷ������ֵ��
	//��֧��SACKʱ����û��ȷ����ʧ��������£���TCP���п�������������ݶ���
	//�����·�ɻ������е�reordering����ֵ��ϵͳ����sysctl_tcp_reordering���г�ʼ����
	//����ʱ��ͬʱ���µ�Ŀ��·�ɻ������reordering����ֵ�С�
	u8	reordering;	/* Packet reordering metric.		*/
	//�ڴ��ͳ�ʱ�󣬼�¼������F-RTO�㷨ʱ���յ�ACK�ε���Ŀ�����ͳ�ʱ�����������F-RTO�㷨�������F-RTO����׶Σ�
	//�ڴ˽׶Σ�����������յ�3����������ȷ��ACK�Σ���ָ�������ģʽ�¡�����ʱ��Ҳ��ʾ��F-RTO����׶�
	u8	frto_counter;	/* Number of new acks after RTO */
	u8	nonagle;	/* Disable Nagle algorithm?             */
	u8	keepalive_probes; /* num of allowed keep alive probes	*/

/* RTT measurement */
	//ƽ����RTT��Ϊ�˱��⸡�����㣬�ǽ���Ŵ�8����洢��
	u32	srtt;		/* smoothed round trip time << 3	*/

	//RTTƽ��ƫ���RTT��RTT��ֵƫ�����ֵ��Ȩƽ�����õ�
	//��ֵԽ��˵��RTT������Խ����
	u32	mdev;	
	
	//����ÿ�η��ʹ����ڶα�ȫ��ȷ�Ϲ����У�RTTƽ��ƫ������ֵ������RTT���������Χ
	u32	mdev_max;	/* maximal mdev for the last rtt period	*/

	//ƽ����RTTƽ��ƫ���mdev����õ�����������RTO
	u32	rttvar;		/* smoothed mdev_max			*/
	
	//��¼snd_una�������ڼ���RTOʱ�Ƚ�snd_una�Ƿ񱻸����ˣ������snd_una���£�����Ҫͬʱ����rttvar
	u32	rtt_seq;	/* sequence number to update rttvar	*/
	
	//Packets which are "in flight"
	//�ѷ��͵���û��ȷ�ϵ�TCP�ε���Ŀ(��snd_nxt - snd_una)
	//��ֵ�Ƕ�̬�ģ������µĶη��������µ�ȷ���յ��������ӻ��С��ֵ
	u32	packets_out;	
	
	//�ش�����û��ȷ�ϵ�TCP����Ŀ
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
 	//ӵ������ʱ����������ֵ
 	//���snd_cwnd < snd_ssthresh�������������׶�
 	u32	snd_ssthresh;	

	//��ǰӵ�����ڴ�С
 	u32	snd_cwnd;		
	//Linear increase counter		
	//A counter used to slow down the rate of increase once we exceed slow start threshold.
	//��ʾ�ڵ�ǰ��ӵ�����ƴ������Ѿ����͵����ݶεĸ���

	//�Դ��ϴε���ӵ�����ڵ�ĿǰΪֹ���յ�����ACK������
	//������ֶ�ֵΪ0����˵���Ѿ�������ӵ�����ڣ��ҵ�ĿǰΪֹ��û�н��յ�ACK�Ρ�
	//����ӵ������֮��ÿ���յ�һ��ACK�ξͻ�ʹsnd_cwnd_cnt��1
	u32	snd_cwnd_cnt;	
	
	//��������ӵ������ֵ����ʼֵΪ65535��֮���ڽ���SYN��ACK��ʱ�����������ȷ���Ƿ��·���������ȡ��Ϣ���¸��ֶΣ�
	//�����TCP���Ӹ�λǰ�������º��ֵ����ĳ���㷨������ٸ��»���Ӧ��·���������У���������ʹ��
	u32	snd_cwnd_clamp; 
	
	//Used as a highwater mark for how much of the congestion window is in use. 
	//It is used to adjust snd_cwnd down when the link is limited by the application rather than the network.
	//��Ӧ�ó�������ʱ����¼��ǰ�ӷ��Ͷ��з�����δ�õ�ȷ�ϵĶ����������ڼ���ӵ������ʱ����ӵ�����ڣ�����ӵ������ʧЧ
	u32	snd_cwnd_used;
	
	//Timestamp for when congestion window last validated. 
	//��¼���һ�ε���ӵ�����ڵ�ʱ��
	
	//��¼���һ�μ���ӵ�����ڵ�ʱ�䡣
	//��ӵ���ڼ䣬���յ�ACK������ӵ�����ڵļ��顣
	//�ڷ�ӵ���ڼ䣬Ϊ�˷�ֹ����Ӧ�ó������ƶ����ӵ������ʧЧ������ڳɹ����Ͷκ�����б�ҪҲ�����ӵ������
	u32	snd_cwnd_stamp;

	//���򻺴���У������ݴ���յ��������TCP��
	struct sk_buff_head	out_of_order_queue;

	//��ǰ�Ľ��մ���(ͨ����Զ˵Ĵ���)��С
 	u32	rcv_wnd;
	//�Ѿ����뵽���Ͷ����е����һ���ֽڵ����
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */

/*	SACKs data	*/
	//�洢���ڻظ��Զ�SACK����Ϣ
	//duplicate_sack�洢D-SACK��Ϣ��selective_acks�洢SACK��Ϣ��
	//�ڻظ�SACKʱ�����ȡ��D-SACK��SACK��Ϣ�����ڴ�����յ�����Ķ�ʱ��������������ֶ���������Ӧ����Ϣ
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	//�洢���յ���SACKѡ�����Ϣ
	struct tcp_sack_block_wire recv_sack_cache[4];
	///��SACKȷ�ϵ����б��Ķ���������ʼ���к�
	u32	highest_sack;	/* Start seq of globally highest revd SACK(validity guaranteed only if sacked_out > 0) */

	/* from STCP, retrans queue hinting */
	//һ����ӵ��״̬û�г�����û�н���Loss״̬ʱ�����ش������У�������һ�α�ǼǷ���δ��ʧ�����һ���Σ�
	//��ҪΪ�˼��ٶ��ش����еı�ǲ�����
	struct sk_buff* lost_skb_hint;
	
	//һ����ӵ��״̬û�г�����û�н���Loss״̬ʱ�����ش������У���¼��һ�α�ǼǷ���δ��ʧ�����һ��SKB��
	//��ҪΪ�˼��ٶ��ش����еı�ǲ�����
	struct sk_buff *scoreboard_skb_hint;

	//���ڼ�¼�ϴ��ش���λ�á�
	//retransmit_skb_hintλ��֮ǰ�Ķξ������ش�������Ϊ�ش��Ķ�Ҳ�Ѿ���ʧ����������ΪNULL�������ش�
	//�ִ�sk_write_queue��ʼ����ʹ�öβ�δ������ʧ��
	//��������Ҳ���������˼������ϵͳ����sysctl_tcp_reorderingҲ�������й�ϵ
	struct sk_buff *retransmit_skb_hint;

	//��֧��SACK��FACKʱ�����ش�����SACK���еĿ�϶�еĶ�ʱ�����ڼ�¼������������������δ���ش���λ�ã��´ο��ԴӴ�λ�ü�������
	//����ش��ˣ����´δ��ش����ж������´���
	struct sk_buff *forward_skb_hint;

	//SACKѡ���Ŀ���·����ʹ�ã��ϴε�һ��SACK��Ľ�����
	//fastpath_skb_hint��¼��һ�δ���SACKѡ��������Ŷε�SKB������һ�δ���SACKѡ��Ŀ�ʼ��
	//��fastpath_cnt_hint��¼��һ�μ���õ���fackets_out��
	//Ŀ����Ϊ����ӵ��״̬û�з����仯����յ�SACKû�з��ͱ仯������£����ٶ�fackets_out��sacked_out�ȵļ���
	struct sk_buff *fastpath_skb_hint;

	/* ����·����ʹ�ã��ϴμ�¼��fack_count�����ڼ����ۼ� */
	int     fastpath_cnt_hint;	/* Lags behind by current skb's pcount
					 * compared to respective fackets_out */
	//lost_skb_hint�ĸ���xxx
	int     lost_cnt_hint;
	//retransmit_skb_hint�ĸ���xxx
	int     retransmit_cnt_hint;

	u32	lost_retrans_low;	/* Sent seq after any rxmit (lowest) */
	//Advertised MSS
	//�����ܽ��յ�MSS����, ��������ʱ����ͨ��Զ�
	//��ֵ��·�ɻ�������MSS����ֵ(RTAX_ADVMSS)���г�ʼ����
	//��·�ɻ�������MSS����ֵ��ֱ��ȡ�������豸�ӿڵ�MTU��ȥIP�ײ���TCP�ײ��ĳ��ȣ�һ����1460���μ�rt_set_nexthop()��
	u16	advmss;		
	
	//������FRTO�㷨������£�·��MTU̽��ɹ�������ӵ������Disorder��Recovery��Loss״̬ʱ�����ssthreshֵ��
	//��Ҫ������ӵ�����ڳ���ʱ���ָ�ӵ�����Ƶ���������ֵ��
	//��prior_ssthresh������Ϊ0ʱ��	avoid increasing the congestion window to a very high value when undo from 
	//a non-open state, (tcp_undo_cwr())
	u16	prior_ssthresh; /* ssthresh saved at recovery start	*/
	
	//Packets lost by network. TCP has no explicit "loss notification" feedback from network (for now).
	//It means that this number can be only _guessed_. Actually, it is the heuristics to predict lossage that
	//distinguishes different algorithms.
	//an estimation of the number of segments lost in the network.
	//�����ж�ʧ�����ݰ��ļ�������һ������ֵ��ȡ���ھ���ʵ��
	//tp->lost_out is incremented in tcp_mark_head_lost() even if we are in a disorder state or an open state.
	u32	lost_out;	
	//Packets, which arrived to receiver out of order and hence not ACKed. With SACKs this number is simply
	//amount of SACKed data. Even without SACKs it is easy to give pretty reliable estimate of this number,
	//counting duplicate ACKs.
	//����SACKʱ��ͨ��SACK��TCPѡ���ʶȷ�ϵ��ѽ��յ��ε�����
	//������SACKʱ����ʶ���յ��ظ�ȷ�ϵĴ�������ֵ�ڽ��յ�ȷ�������ݵĶ�ʱ�����
	u32	sacked_out;	

	//��¼snd_una��SACKѡ����Ŀǰ���շ��յ��Ķ��������Ŷ�֮��Ķ�����
	//FACK�㷨��SACKѡ�������㶪ʧ�������ϵĶ���������:
	//lost_out = fackets_out - sacked_out
	//left_out = fackets_out
	u32	fackets_out;	/* FACK'd packets			*/

	//��¼����ӵ��ʱ�����ķ������(snd_nxt)�� ��ʶ�ش����е�β��
	//tp->high_seq is set to the highest sequence number that has been
	//transmitted at that point of time when we enter loss or recovery (cwr) state.
	u32	high_seq;	

	//����������ʱ����¼��һ��SYN�εķ���ʱ�䣬�������ACK����Ƿ����
	//�����ݴ���׶Σ������ͳ�ʱ�ش�ʱ����¼�ش��׶ι��̵�һ���ش��εķ���ʱ�䣬�����ж��Ƿ���Խ���ӵ������
	// timestamp of the first retransmission, used to detect false retransmissions
	//��Ȼretrans_outΪ0ʱ, retrans_stampҲҪΪ0
	u32	retrans_stamp;	
	//��ʹ��F-RTO�㷨���з��ͳ�ʱ���������Recovery�����ش��������Loss��ʼ������ʱ��
	//��¼��ʱsnd_una������ش�����ʼ�㡣���Ǽ���Ƿ���Խ���ӵ������������֮һ��
	//һ�������ӵ���������������ӵ������Loss״̬״̬�����㡣
	///��ʾ�����ش�ʱ��snd_una
	///��ʱ�ش���FRTOʱ��¼��snd_una
	//set to tp->snd_una when we enter the recovery phase and retransmit data,
	//this is set to unACKed sequence number (tp->snd_una) when we enter the congestion state. 
	//0 means that we don't want to undo from the congestion state (tcp_may_undo())
	u32	undo_marker;	/* tracking retrans started here. */
	///��¼�ش����ݰ��ĸ��������undo_retrans����0��
    ///��˵��֮ǰ���ش����ǲ���Ҫ�ģ�����ӵ������������

	//�ڻָ�ӵ������֮ǰ�ɽ��г������ش��������ڽ���FRTO�㷨��ӵ������״̬Lossʱ���㣬
	//���ش�ʱ�������Ǽ���Ƿ���Խ���ӵ������������֮һ��
	//helps in detecting false retransmits in recovery/loss state
	int	undo_retrans;	/* number of undoable retransmissions. */
	u32	urg_seq;	/* Seq of received urgent pointer */
	u16	urg_data;	/* Saved octet of OOB data and control flags */
	u8	urg_mode;	/* In urgent mode		*/
	//��ʾӵ��֪ͨ״̬λ: TCP_ECN_OK / TCP_ECN_QUEUE_CWR / TCP_ECN_DEMAND_CWR
	u8	ecn_flags;	
	u32	snd_up;		/* Urgent pointer		*/

	//���������������ش�����
	u32	total_retrans;	
	//������sysctl_tcp_abc(Appropriate Byte Counting)֮����ӵ������׶Σ�������ȷ�ϵ��ֽ������μ�RFC3465
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
