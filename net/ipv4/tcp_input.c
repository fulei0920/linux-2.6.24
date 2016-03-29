/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Version:	$Id: tcp_input.c,v 1.243 2002/02/01 22:01:04 davem Exp $
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

/*
 * Changes:
 *		Pedro Roque	:	Fast Retransmit/Recovery.
 *					Two receive queues.
 *					Retransmit queue handled by TCP.
 *					Better retransmit timer handling.
 *					New congestion avoidance.
 *					Header prediction.
 *					Variable renaming.
 *
 *		Eric		:	Fast Retransmit.
 *		Randy Scott	:	MSS option defines.
 *		Eric Schenk	:	Fixes to slow start algorithm.
 *		Eric Schenk	:	Yet another double ACK bug.
 *		Eric Schenk	:	Delayed ACK bug fixes.
 *		Eric Schenk	:	Floyd style fast retrans war avoidance.
 *		David S. Miller	:	Don't allow zero congestion window.
 *		Eric Schenk	:	Fix retransmitter so that it sends
 *					next packet on ack of previous packet.
 *		Andi Kleen	:	Moved open_request checking here
 *					and process RSTs for open_requests.
 *		Andi Kleen	:	Better prune_queue, and other fixes.
 *		Andrey Savochkin:	Fix RTT measurements in the presence of
 *					timestamps.
 *		Andrey Savochkin:	Check sequence numbers correctly when
 *					removing SACKs due to in sequence incoming
 *					data segments.
 *		Andi Kleen:		Make sure we never ack data there is not
 *					enough room for. Also make this condition
 *					a fatal error if it might still happen.
 *		Andi Kleen:		Add tcp_measure_rcv_mss to make
 *					connections with MSS<min(MTU,ann. MSS)
 *					work without delayed acks.
 *		Andi Kleen:		Process packets with PSH set in the
 *					fast path.
 *		J Hadi Salim:		ECN support
 *	 	Andrei Gurtov,
 *		Pasi Sarolahti,
 *		Panu Kuhlberg:		Experimental audit of TCP (re)transmission
 *					engine. Lots of bugs are found.
 *		Pasi Sarolahti:		F-RTO for dealing with spurious RTOs
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/ipsec.h>
#include <asm/unaligned.h>
#include <net/netdma.h>

//±êÊ¶ÊÇ·ñÆôÓÃTCPÊ±¼ä´ÁÑ¡Ïî¡£Ä¬ÈÏÖµÎª1(true)¡£
//Ê±¼ä´Á¿ÉÒÔÊ¹Á¬½ÓµÄÁ½¶ËºÜ·½±ãµÄ²âÁ¿RTT£¬Í¬Ê±»¹¿ÉÒÔ±ÜÃâÐòºÅµÄ»ØÈÆ£¬Òò´ËÎªÁËÊµÏÖ¸üºÃµÄÐÔÄÜÓ¦¸ÃÆôÓÃ¸ÃÑ¡Ïî¡£²Î¼ûRFC1323
int sysctl_tcp_timestamps __read_mostly = 1;
//±êÊ¶ÊÇ·ñÆôÓÃTCP´°¿ÚÀ©´óÒò×ÓÑ¡Ïî¡£Ä¬ÈÏÖµÎª1(true)¡£
//Í¨³£Çé¿öÏÂTCPÔÊÐí´°¿Ú³ß´çÎª65535B£¬µ«¶ÔÓÚ´ø¿íºÜ¸ßµÄÍøÂç¶øÑÔÕâ¸öÖµ¿ÉÄÜ»¹ÊÇÌ«Ð¡£¬´ËÊ±Èç¹ûÆôÓÃÁË¸ÃÑ¡Ïî£¬¿ÉÊ¹TCP»¬¶¯´°¿Ú
//´óÐ¡Ôö´óÊý¸öÊýÁ¿¼¶£¬´Ó¶øÌá¹©Êý¾Ý´«ÊäµÄÄÜÁ¦£¬²Î¼ûRFC1323
int sysctl_tcp_window_scaling __read_mostly = 1;
//±êÊ¶ÊÇ·ñÆôÓÃÑ¡ÔñÐÔÈ·ÈÏSACKSÑ¡Ïî¡£Ä¬ÈÏÖµÎª1(true)¡£
//SACK¿ÉÒÔÓÃÀ´²éÕÒÌØ¶¨µÄ¶ªÊ§µÄ¶Î£¬Òò´ËÓÐÖúÓÚ¿ìËÙ»Ö¸´×´Ì¬¡£Í¬Ê±£¬ÆôÓÃSACK£¬½ÓÊÕ·½¿ÉÒÔÓÐÑ¡ÔñµØÓ¦´ðÂÒÐò½ÓÊÕµ½µÄ¶Î£¬
//¿É°ïÖú·¢ËÍ·½È·¶¨¶ªÊ§µÄ¶Î£¬½ø¶ø·¢ËÍ·½Ö»Ðè·¢ËÍ¶ªÊ§µÄ¶Î£¬ÒÔÌá¸ßÐÔÄÜ¡£
//¶ÔÓÚ¹ãÓòÍøÍ¨ÐÅÀ´ËµÓ¦¸ÃÆôÓÃ¸ÃÑ¡Ïî£¬µ«ÊÇÕâ»áÔö¼ÓCPUµÄ¸ººÉ£¬²Î¼ûRFC2018

int sysctl_tcp_sack __read_mostly = 1;
//±êÖ¾ÊÇ·ñÆôÓÃFACKÓµÈû±ÜÃâÓë¿ìËÙÖØ´«¹¦ÄÜ¡£
//×¢Òâ£¬Ö»ÓÐµ±ÆôÓÃsysctl_tcp_sackÊ±£¬¸ÃÏµÍ³²ÎÊý²ÅÓÐÐ§
int sysctl_tcp_fack __read_mostly = 1;
//ÔÚ²»Ö§³ÖSACKÊ±£¬ÎªÓÉÓÚÁ¬½Ó½ÓÊÕµ½ÖØ¸´È·ÈÏ¶ø½øÈë¿ìËÙ»Ö¸´½×¶ÎµÄÖØ¸´È·ÈÏÊýãÐÖµ¡£
//ÔÚÖ§³ÖSACKÊ±£¬ÔÚÃ»ÓÐÈ·¶¨¶ªÊ§°üµÄÇé¿öÏÂ£¬ÊÇTCPÁ÷ÖÐ¿ÉÒÔÖØÅÅµÄÊý¾Ý¶ÎÊý¡£
//Ä¬ÈÏÖµÎª3(¸ö)¡£Èç¹û½µµÍ´ËÖµ£¬¿ÉÄÜ»áµ¼ÖÂÍøÂçÐÔÄÜ±ä²î¡£
int sysctl_tcp_reordering __read_mostly = TCP_FASTRETRANS_THRESH;
//±êÊ¶ÊÇ·ñÆôÓÃTCPµÄÏÔÊ¾ÓµÈûÍ¨Öª¹¦ÄÜ¡£
int sysctl_tcp_ecn __read_mostly;
//±êÊ¶ÊÇ·ñÖ§³ÖTCP·¢ËÍÈ·ÈÏ¶ÎÖÐSACKÑ¡Ïî´æÔÚD-SACK(duplicate-SACK)¡£
int sysctl_tcp_dsack __read_mostly = 1;
//ÎªÓ¦ÓÃ³ÌÐò±£Áômax(window/2^sysctl_tcp_app_win, mss)´óÐ¡µÄ´°¿Ú¡£µ±Îª0Ê±±íÊ¾²»ÐèÒª»º³å¡£Ä¬ÈÏÖµÎª31
int sysctl_tcp_app_win __read_mostly = 31;
//ÔÚ¿ªÆôÁËÍ¨¹ýµ÷½Ú½ÓÊÕ´°¿ÚÀ´½øÐÐÁ÷Á¿¿ØÖÆµÄÇé¿öÏÂ£¬¼ÆËãµ÷Õû½ÓÊÕ»º´æºÍ½ÓÊÕ´°¿ÚÊ±£¬
//¶ÔÓÃÀ´¼ÆËã½ÓÊÕ»º´æµÄ²ÎÊý½øÐÐÎ¢µ÷¡£Ä¬ÈÏÖµÎª2¡£
//Ëã·¨²Î¼ûtcp_win_from_space(int space)£¬Æä²ÎÊýspace¾ÍÊÇ½«±»Î¢µ÷µÄ²ÎÊý
int sysctl_tcp_adv_win_scale __read_mostly = 2;
int sysctl_tcp_stdurg __read_mostly;
int sysctl_tcp_rfc1337 __read_mostly;
int sysctl_tcp_max_orphans __read_mostly = NR_FILE;
//±êÊ¶ÊÇ·ñÆôÓÃF-RTO
//ÆôÓÃF-RTO£¬»áÆôÓÃÓÅ»¯ºóµÄTCPÖØ´«Ëã·¨¡£ÕâÔÚÎÞÏß»·¾³ÖÐÌØ±ðÓÐÐ§£¬
//ÒòÎªÍ¨³£ÊÇÓÉÓÚÎÞÏßµç¸ÉÈÅ¶ø²»ÊÇÓÉÓÚÂ·ÓÉÆ÷ÓµÈûµ¼ÖÂËæ»ú¶ª°ü
int sysctl_tcp_frto __read_mostly = 2;
int sysctl_tcp_frto_response __read_mostly;
int sysctl_tcp_nometrics_save __read_mostly;
//±êÊ¾ÊÇ·ñÆô¶¯×Ô¶¯µ÷½Ú½ÓÊÜ»º³åÇø´óÐ¡¡£Ä¬ÈÏÖµÎª1(true)
//Èç¹ûÆôÓÃ£¬TCP»á×Ô¶¯µØµ÷Õû½ÓÊÕ»º³åÇøµÄ´óÐ¡£¬ÒÔ´ËÀ´½øÐÐÁ÷Á¿¿ØÖÆ£¬ÔÚÂú×ã»º³åÇø´óÐ¡²»ÄÜ³¬¹ýÏµÍ³²ÎÊýsysctl_tcp_rmem[2](high)µÄÌõ¼þÏÂ£¬Ìá¹©×î´óµÄÍÌÍÂÁ¿
int sysctl_tcp_moderate_rcvbuf __read_mostly = 1;
//±êÊ¶ÊÇ·ñÆôÓÃABC(Appropriate Byte Count)¡£
// 0(Ä¬ÈÏÖµ) -- ½ûÓÃABC£¬Ã¿´ÎÊÕµ½ACK¶¼»áÔö³¤ÓµÈû´°¿Ú
// 1		   -- ÀÛ¼ÆÈ·ÈÏÁËÒ»¸öÈ«³ß´çµÄ¶ÎÖ®ºó²Å»áµÝÔöÓµÈû´°¿Ú
// 2         -- Èç¹û½ÓÊÕ·½ÆôÓÃÁËÑÓÊ±È·ÈÏ£¬ÀÛ¼ÆÈ·ÈÏÁËÁ½¸öÈ«³ß´çµÄ¶ÎÖ®ºó²Å»áµÝÔöÓµÈû´°¿Ú
//ABC¶¨ÒåÔÚRFC3465ÖÐ£¬ÊÇ¸ù¾Ý½ÓÊÕµ½µÄACKÈ·ÈÏµÄ×Ö½ÚÊýÀ´¿ØÖÆÓµÈû´°¿ÚÔö³¤µÄÒ»ÖÖ·½·¨
int sysctl_tcp_abc __read_mostly;

//½ÓÊÕµ½µÄACK¶ÎÊÇ¸ººÉÊý¾ÝÐ¯´øµÄ
#define FLAG_DATA			0x01 		/* Incoming frame contained data.		*/
//½ÓÊÕµ½µÄACK¶Î¸üÐÂÁË·¢ËÍ´°¿Ú
#define FLAG_WIN_UPDATE		0x02 		/* Incoming ACK was a window update.	*/
//½ÓÊÕµ½µÄACK¶ÎÈ·ÈÏÁËÐÂµÄÊý¾Ý
#define FLAG_DATA_ACKED		0x04 		/* This ACK acknowledged new data.		*/
//½ÓÊÕµ½µÄACK¶ÎÈ·ÈÏÁË±»ÖØ´«¹ýµÄÊý¾Ý
#define FLAG_RETRANS_DATA_ACKED	0x08 	/* "" "" some of which was retransmitted.	*/
//½ÓÊÕµÄACK¶ÎÈ·ÈÏÁËSYN¶Î
#define FLAG_SYN_ACKED		0x10 /* This ACK acknowledged SYN.		*/
//ÊÇÐÂµÄSACK(SACKÈ·ÈÏÁËÐÂµÄÊý¾Ý)
#define FLAG_DATA_SACKED	0x20 /* New SACK.				*/
//ÔÚACK¶ÎÖÐ´æÔÚECE±êÖ¾£¬ÏÔÊ¾ÊÕµ½ÓµÈûÍ¨Öª
#define FLAG_ECE			0x40 /* ECE in this ACK				*/
//ÓÉSACK±êÊ¶µÄÊý¾ÝÒÑ¶ªÊ§
#define FLAG_DATA_LOST		0x80 /* SACK detected data lossage.		*/
//ÔÚÂýËÙÂ·¾¶ÖÐ´¦ÀíµÄ
#define FLAG_SLOWPATH		0x100 /* Do not skip RFC checks for window update.*/
#define FLAG_ONLY_ORIG_SACKED	0x200 /* SACKs only non-rexmit sent before RTO */
#define FLAG_SND_UNA_ADVANCED	0x400 	/* Snd_una was changed (!= FLAG_DATA_ACKED) */
//
#define FLAG_DSACKING_ACK	0x800 /* SACK blocks contained D-SACK info */
#define FLAG_NONHEAD_RETRANS_ACKED	0x1000 /* Non-head rexmitted data was ACKed */

#define FLAG_ACKED		(FLAG_DATA_ACKED|FLAG_SYN_ACKED)
#define FLAG_NOT_DUP		(FLAG_DATA|FLAG_WIN_UPDATE|FLAG_ACKED)
#define FLAG_CA_ALERT		(FLAG_DATA_SACKED|FLAG_ECE)
#define FLAG_FORWARD_PROGRESS	(FLAG_ACKED|FLAG_DATA_SACKED)
#define FLAG_ANY_PROGRESS	(FLAG_FORWARD_PROGRESS|FLAG_SND_UNA_ADVANCED)

#define IsSackFrto() (sysctl_tcp_frto == 0x2)

#define TCP_REMNANT (TCP_FLAG_FIN|TCP_FLAG_URG|TCP_FLAG_SYN|TCP_FLAG_PSH)
#define TCP_HP_BITS (~(TCP_RESERVED_BITS|TCP_FLAG_PSH))

/* Adapt the MSS value used to make delayed ack decision to the
 * real world.
 */
static void tcp_measure_rcv_mss(struct sock *sk,
				const struct sk_buff *skb)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const unsigned int lss = icsk->icsk_ack.last_seg_size;
	unsigned int len;

	icsk->icsk_ack.last_seg_size = 0;

	/* skb->len may jitter because of SACKs, even if peer
	 * sends good full-sized frames.
	 */
	len = skb_shinfo(skb)->gso_size ?: skb->len;
	if (len >= icsk->icsk_ack.rcv_mss) {
		icsk->icsk_ack.rcv_mss = len;
	} else {
		/* Otherwise, we make more careful check taking into account,
		 * that SACKs block is variable.
		 *
		 * "len" is invariant segment length, including TCP header.
		 */
		len += skb->data - skb_transport_header(skb);
		if (len >= TCP_MIN_RCVMSS + sizeof(struct tcphdr) ||
		    /* If PSH is not set, packet should be
		     * full sized, provided peer TCP is not badly broken.
		     * This observation (if it is correct 8)) allows
		     * to handle super-low mtu links fairly.
		     */
		    (len >= TCP_MIN_MSS + sizeof(struct tcphdr) &&
		     !(tcp_flag_word(tcp_hdr(skb)) & TCP_REMNANT))) {
			/* Subtract also invariant (if peer is RFC compliant),
			 * tcp header plus fixed timestamp option length.
			 * Resulting "len" is MSS free of SACK jitter.
			 */
			len -= tcp_sk(sk)->tcp_header_len;
			icsk->icsk_ack.last_seg_size = len;
			if (len == lss) {
				icsk->icsk_ack.rcv_mss = len;
				return;
			}
		}
		if (icsk->icsk_ack.pending & ICSK_ACK_PUSHED)
			icsk->icsk_ack.pending |= ICSK_ACK_PUSHED2;
		icsk->icsk_ack.pending |= ICSK_ACK_PUSHED;
	}
}

static void tcp_incr_quickack(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	unsigned quickacks = tcp_sk(sk)->rcv_wnd / (2 * icsk->icsk_ack.rcv_mss);

	if (quickacks==0)
		quickacks=2;
	if (quickacks > icsk->icsk_ack.quick)
		icsk->icsk_ack.quick = min(quickacks, TCP_MAX_QUICKACKS);
}

void tcp_enter_quickack_mode(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	tcp_incr_quickack(sk);
	icsk->icsk_ack.pingpong = 0;
	icsk->icsk_ack.ato = TCP_ATO_MIN;
}

/* Send ACKs quickly, if "quick" count is not exhausted
 * and the session is not interactive.
 */

static inline int tcp_in_quickack_mode(const struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	return icsk->icsk_ack.quick && !icsk->icsk_ack.pingpong;
}

static inline void TCP_ECN_queue_cwr(struct tcp_sock *tp)
{
	if (tp->ecn_flags & TCP_ECN_OK)
		tp->ecn_flags |= TCP_ECN_QUEUE_CWR;
}

static inline void TCP_ECN_accept_cwr(struct tcp_sock *tp, struct sk_buff *skb)
{
	if (tcp_hdr(skb)->cwr)
		tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
}

static inline void TCP_ECN_withdraw_cwr(struct tcp_sock *tp)
{
	tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
}

static inline void TCP_ECN_check_ce(struct tcp_sock *tp, struct sk_buff *skb)
{
	if (tp->ecn_flags&TCP_ECN_OK)
	{
		if (INET_ECN_is_ce(TCP_SKB_CB(skb)->flags))
			tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
		/* Funny extension: if ECT is not set on a segment,
		 * it is surely retransmit. It is not in ECN RFC,
		 * but Linux follows this rule. */
		else if (INET_ECN_is_not_ect((TCP_SKB_CB(skb)->flags)))
			tcp_enter_quickack_mode((struct sock *)tp);
	}
}

static inline void TCP_ECN_rcv_synack(struct tcp_sock *tp, struct tcphdr *th)
{
	if ((tp->ecn_flags&TCP_ECN_OK) && (!th->ece || th->cwr))
		tp->ecn_flags &= ~TCP_ECN_OK;
}

static inline void TCP_ECN_rcv_syn(struct tcp_sock *tp, struct tcphdr *th)
{
	if ((tp->ecn_flags&TCP_ECN_OK) && (!th->ece || !th->cwr))
		tp->ecn_flags &= ~TCP_ECN_OK;
}

static inline int TCP_ECN_rcv_ecn_echo(struct tcp_sock *tp, struct tcphdr *th)
{
	if (th->ece && !th->syn && (tp->ecn_flags & TCP_ECN_OK))
		return 1;
	return 0;
}

/* Buffer size and advertised window tuning.
 *
 * 1. Tuning sk->sk_sndbuf, when connection enters established state.
 */

static void tcp_fixup_sndbuf(struct sock *sk)
{
	int sndmem = tcp_sk(sk)->rx_opt.mss_clamp + MAX_TCP_HEADER + 16 +
		     sizeof(struct sk_buff);

	if (sk->sk_sndbuf < 3 * sndmem)
		sk->sk_sndbuf = min(3 * sndmem, sysctl_tcp_wmem[2]);
}

/* 2. Tuning advertised window (window_clamp, rcv_ssthresh)
 *
 * All tcp_full_space() is split to two parts: "network" buffer, allocated
 * forward and advertised in receiver window (tp->rcv_wnd) and
 * "application buffer", required to isolate scheduling/application
 * latencies from network.
 * window_clamp is maximal advertised window. It can be less than
 * tcp_full_space(), in this case tcp_full_space() - window_clamp
 * is reserved for "application" buffer. The less window_clamp is
 * the smoother our behaviour from viewpoint of network, but the lower
 * throughput and the higher sensitivity of the connection to losses. 8)
 *
 * rcv_ssthresh is more strict window_clamp used at "slow start"
 * phase to predict further behaviour of this connection.
 * It is used for two goals:
 * - to enforce header prediction at sender, even when application
 *   requires some significant "application buffer". It is check #1.
 * - to prevent pruning of receive queue because of misprediction
 *   of receiver window. Check #2.
 *
 * The scheme does not work when sender sends good segments opening
 * window and then starts to feed us spaghetti. But it should work
 * in common situations. Otherwise, we have to rely on queue collapsing.
 */

/* Slow part of check#2. */
static int __tcp_grow_window(const struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	/* Optimize this! */
	int truesize = tcp_win_from_space(skb->truesize)/2;
	int window = tcp_win_from_space(sysctl_tcp_rmem[2])/2; //½ÓÊÕ»º³åÇø³¤¶ÈÉÏÏÞµÄÒ»°ë

	//rcv_ssthresh²»³¬¹ýÒ»°ëµÄ½ÓÊÕ»º³åÇøÉÏÏÞ²ÅÓÐ¿ÉÄÜ
	while (tp->rcv_ssthresh <= window)
	{
		if (truesize <= skb->len)
			return 2 * inet_csk(sk)->icsk_ack.rcv_mss;

		truesize >>= 1;
		window >>= 1;
	}
	return 0;
}

static void tcp_grow_window(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Check #1 */
	if (tp->rcv_ssthresh < tp->window_clamp 			//½ÓÊÕ´°¿Úµ±Ç°ãÐÖµ²»ÄÜ³¬¹ý½ÓÊÕ´°¿ÚµÄÉÏÏÞ
		&& (int)tp->rcv_ssthresh < tcp_space(sk) 		//½ÓÊÕ´°¿Úµ±Ç°ãÐÖµ²»ÄÜ³¬¹ýÊ£Óà½ÓÊÕ»º´æµÄ3/4£¬¼´network buffer
		&& !tcp_memory_pressure)						//Ã»ÓÐÄÚ´æÑ¹Á¦
	{
		int incr;

		/* Check #2. Increase window, if skb with such overhead
		 * will fit to rcvbuf in future.
		 */

		//¸ù¾Ý¶îÍâ¿ªÏúµÄÄÚ´æÕ¼µÄ±ÈÖØ£¬À´ÅÐ¶ÏÊÇ·ñÔÊÐíÔö³¤¡£¶îÍâµÄÄÚ´æ¿ªÏú(overhead)Ö¸µÄÊÇ£º
		//sk_buff¡¢skb_shared_info½á¹¹Ìå£¬ÒÔ¼°Ð­ÒéÍ·¡£ÓÐÐ§µÄÄÚ´æ¿ªÏúÖ¸µÄÊÇÊý¾Ý¶ÎµÄ³¤¶È¡£
		//£¨1£©¶îÍâ¿ªÏúÐ¡ÓÚ25%£¬Ôòrcv_ssthreshÔö³¤Á½¸ö±¾¶Ë×î´ó½ÓÊÕMSS¡£
		//£¨2£©¶îÍâ¿ªÏú´óÓÚ25%£¬·ÖÎªÁ½ÖÖÇé¿ö¡£
		
		 //Èç¹ûÓ¦ÓÃ²ãÊý¾ÝÕ¼Õâ¸öskb×Ü¹²ÏûºÄÄÚ´æµÄ75%ÒÔÉÏ£¬ÔòËµÃ÷Õâ¸öÊý¾Ý±¨ÊÇ´óµÄÊý¾Ý±¨£¬ 
         //ÄÚ´æµÄ¶îÍâ¿ªÏú½ÏÐ¡¡£ÕâÑùÒ»À´ÎÒÃÇ¿ÉÒÔ·ÅÐÄµÄÔö³¤rcv_ssthreshÁË¡£ 
		if (tcp_win_from_space(skb->truesize) <= skb->len)
			incr = 2*tp->advmss;	//Ôö¼ÓÁ½¸ö±¾¶Ë×î´ó½ÓÊÕMSS
		else
			incr = __tcp_grow_window(sk, skb);  // ¿ÉÄÜÔö´órcv_ssthresh£¬Ò²¿ÉÄÜ²»Ôö´ó£¬¾ßÌåÊÓ¶îÍâÄÚ´æ¿ªÏúºÍÊ£Óà»º´æ¶ø¶¨

		if (incr)
		{
			tp->rcv_ssthresh = min(tp->rcv_ssthresh + incr, tp->window_clamp);
			inet_csk(sk)->icsk_ack.quick |= 1;  //ÔÊÐí¿ìËÙACK
		}
	}
}

/* 3. Tuning rcvbuf, when connection enters established state. */

static void tcp_fixup_rcvbuf(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int rcvmem = tp->advmss + MAX_TCP_HEADER + 16 + sizeof(struct sk_buff);

	/* Try to select rcvbuf so that 4 mss-sized segments
	 * will fit to window and corresponding skbs will fit to our rcvbuf.
	 * (was 3; 4 is minimum to allow fast retransmit to work.)
	 */
	while (tcp_win_from_space(rcvmem) < tp->advmss)
		rcvmem += 128;
	if (sk->sk_rcvbuf < 4 * rcvmem)
		sk->sk_rcvbuf = min(4 * rcvmem, sysctl_tcp_rmem[2]);
}

/* 4. Try to fixup all. It is made immediately after connection enters
 *    established state.
 */
static void tcp_init_buffer_space(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int maxwin;

	if (!(sk->sk_userlocks & SOCK_RCVBUF_LOCK))
		tcp_fixup_rcvbuf(sk);
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK))
		tcp_fixup_sndbuf(sk);

	tp->rcvq_space.space = tp->rcv_wnd;

	maxwin = tcp_full_space(sk);

	if (tp->window_clamp >= maxwin)
	{
		tp->window_clamp = maxwin;

		if (sysctl_tcp_app_win && maxwin > 4 * tp->advmss)
			tp->window_clamp = max(maxwin - (maxwin >> sysctl_tcp_app_win), 4 * tp->advmss);
	}

	/* Force reservation of one segment. */
	if (sysctl_tcp_app_win && 
		tp->window_clamp > 2 * tp->advmss &&
	    tp->window_clamp + tp->advmss > maxwin)
		tp->window_clamp = max(2 * tp->advmss, maxwin - tp->advmss);

	tp->rcv_ssthresh = min(tp->rcv_ssthresh, tp->window_clamp);
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* 5. Recalculate window clamp after socket hit its memory bounds. */
static void tcp_clamp_window(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	icsk->icsk_ack.quick = 0;

	if (sk->sk_rcvbuf < sysctl_tcp_rmem[2] &&
	    !(sk->sk_userlocks & SOCK_RCVBUF_LOCK) &&
	    !tcp_memory_pressure &&
	    atomic_read(&tcp_memory_allocated) < sysctl_tcp_mem[0]) {
		sk->sk_rcvbuf = min(atomic_read(&sk->sk_rmem_alloc),
				    sysctl_tcp_rmem[2]);
	}
	if (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf)
		tp->rcv_ssthresh = min(tp->window_clamp, 2U*tp->advmss);
}


/* Initialize RCV_MSS value.
 * RCV_MSS is an our guess about MSS used by the peer.
 * We haven't any direct information about the MSS.
 * It's better to underestimate the RCV_MSS rather than overestimate.
 * Overestimations make us ACKing less frequently than needed.
 * Underestimations are more easy to detect and fix by tcp_measure_rcv_mss().
 */
void tcp_initialize_rcv_mss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int hint = min_t(unsigned int, tp->advmss, tp->mss_cache);

	hint = min(hint, tp->rcv_wnd/2);
	hint = min(hint, TCP_MIN_RCVMSS);
	hint = max(hint, TCP_MIN_MSS);

	inet_csk(sk)->icsk_ack.rcv_mss = hint;
}

/* Receiver "autotuning" code.
 *
 * The algorithm for RTT estimation w/o timestamps is based on
 * Dynamic Right-Sizing (DRS) by Wu Feng and Mike Fisk of LANL.
 * <http://www.lanl.gov/radiant/website/pubs/drs/lacsi2001.ps>
 *
 * More detail on this code can be found at
 * <http://www.psc.edu/~jheffner/senior_thesis.ps>,
 * though this reference is out of date.  A new paper
 * is pending.
 */
static void tcp_rcv_rtt_update(struct tcp_sock *tp, u32 sample, int win_dep)
{
	u32 new_sample = tp->rcv_rtt_est.rtt;
	long m = sample;

	if (m == 0)
		m = 1;

	if (new_sample != 0) {
		/* If we sample in larger samples in the non-timestamp
		 * case, we could grossly overestimate the RTT especially
		 * with chatty applications or bulk transfer apps which
		 * are stalled on filesystem I/O.
		 *
		 * Also, since we are only going for a minimum in the
		 * non-timestamp case, we do not smooth things out
		 * else with timestamps disabled convergence takes too
		 * long.
		 */
		if (!win_dep) {
			m -= (new_sample >> 3);
			new_sample += m;
		} else if (m < new_sample)
			new_sample = m << 3;
	} else {
		/* No previous measure. */
		new_sample = m << 3;
	}

	if (tp->rcv_rtt_est.rtt != new_sample)
		tp->rcv_rtt_est.rtt = new_sample;
}

static inline void tcp_rcv_rtt_measure(struct tcp_sock *tp)
{
	if (tp->rcv_rtt_est.time == 0)
		goto new_measure;
	if (before(tp->rcv_nxt, tp->rcv_rtt_est.seq))
		return;
	tcp_rcv_rtt_update(tp,
			   jiffies - tp->rcv_rtt_est.time,
			   1);

new_measure:
	tp->rcv_rtt_est.seq = tp->rcv_nxt + tp->rcv_wnd;
	tp->rcv_rtt_est.time = tcp_time_stamp;
}

static inline void tcp_rcv_rtt_measure_ts(struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	if (tp->rx_opt.rcv_tsecr && (TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq >= inet_csk(sk)->icsk_ack.rcv_mss))
		tcp_rcv_rtt_update(tp, tcp_time_stamp - tp->rx_opt.rcv_tsecr, 0);
}

/*
 * This function should be called every time data is copied to user space.
 * It calculates the appropriate TCP receive buffer space.
 */
void tcp_rcv_space_adjust(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int time;
	int space;

	if (tp->rcvq_space.time == 0)
		goto new_measure;

	time = tcp_time_stamp - tp->rcvq_space.time;
	if (time < (tp->rcv_rtt_est.rtt >> 3) ||
	    tp->rcv_rtt_est.rtt == 0)
		return;

	space = 2 * (tp->copied_seq - tp->rcvq_space.seq);

	space = max(tp->rcvq_space.space, space);

	if (tp->rcvq_space.space != space) {
		int rcvmem;

		tp->rcvq_space.space = space;

		if (sysctl_tcp_moderate_rcvbuf && !(sk->sk_userlocks & SOCK_RCVBUF_LOCK)) 
		{
			int new_clamp = space;

			/* Receive space grows, normalize in order to
			 * take into account packet headers and sk_buff
			 * structure overhead.
			 */
			space /= tp->advmss;
			if (!space)
				space = 1;
			rcvmem = (tp->advmss + MAX_TCP_HEADER +
				  16 + sizeof(struct sk_buff));
			while (tcp_win_from_space(rcvmem) < tp->advmss)
				rcvmem += 128;
			space *= rcvmem;
			space = min(space, sysctl_tcp_rmem[2]);
			if (space > sk->sk_rcvbuf) {
				sk->sk_rcvbuf = space;

				/* Make the window clamp follow along.  */
				tp->window_clamp = new_clamp;
			}
		}
	}

new_measure:
	tp->rcvq_space.seq = tp->copied_seq;
	tp->rcvq_space.time = tcp_time_stamp;
}

/* There is something which you must keep in mind when you analyze the
 * behavior of the tp->ato delayed ack timeout interval.  When a
 * connection starts up, we want to ack as quickly as possible.  The
 * problem is that "good" TCP's do slow start at the beginning of data
 * transmission.  The means that until we send the first few ACK's the
 * sender will sit on his end and only queue most of his data, because
 * he can only send snd_cwnd unacked packets at any given time.  For
 * each ACK we send, he increments snd_cwnd and transmits more of his
 * queue.  -DaveM
 */
static void tcp_event_data_recv(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	u32 now;

	/* ½ÓÊÕµ½ÁËÊý¾Ý£¬ÉèÖÃACKÐèµ÷¶È±êÖ¾*/
	inet_csk_schedule_ack(sk);

	tcp_measure_rcv_mss(sk, skb);

	tcp_rcv_rtt_measure(tp);

	now = tcp_time_stamp;

	/* ÒÔÏÂÎª¸ù¾Ý½ÓÊÕ¼ä¸ô¸üÐÂicsk_ack.ato£¬¸ÃÖµÖ÷ÒªÓÃÓÚÅÐ¶ÏpingpongÄ£Ê½¼ûº¯Êýtcp_event_data_sent */  
	if (!icsk->icsk_ack.ato)
	{
		/* The _first_ data packet received, initialize
		 * delayed ACK engine.
		 */
		tcp_incr_quickack(sk);
		icsk->icsk_ack.ato = TCP_ATO_MIN;
	} else {
		int m = now - icsk->icsk_ack.lrcvtime;

		if (m <= TCP_ATO_MIN/2) {
			/* The fastest case is the first. */
			icsk->icsk_ack.ato = (icsk->icsk_ack.ato >> 1) + TCP_ATO_MIN / 2;
		} else if (m < icsk->icsk_ack.ato) {
			icsk->icsk_ack.ato = (icsk->icsk_ack.ato >> 1) + m;
			if (icsk->icsk_ack.ato > icsk->icsk_rto)
				icsk->icsk_ack.ato = icsk->icsk_rto;
		} else if (m > icsk->icsk_rto) {
			/* Too long gap. Apparently sender failed to
			 * restart window, so that we send ACKs quickly.
			 */
			tcp_incr_quickack(sk);
			sk_stream_mem_reclaim(sk);
		}
	}
	icsk->icsk_ack.lrcvtime = now;

	TCP_ECN_check_ce(tp, skb);
	// Ã¿´Î½ÓÊÕµ½À´×Ô¶Ô·½µÄÒ»¸öTCPÊý¾Ý±¨£¬ÇÒÊý¾Ý±¨³¤¶È´óÓÚ128×Ö½ÚÊ±£¬ÎÒÃÇÐèÒªµ÷ÓÃtcp_grow_window£¬Ôö¼Órcv_ssthreshµÄÖµ£¬
	//Ò»°ãÃ¿´ÎÎªrcv_ssthreshÔö³¤Á½±¶µÄmss£¬Ôö¼ÓµÄÌõ¼þÊÇrcv_ssthreshÐ¡ÓÚwindow_clamp,²¢ÇÒ rcv_ssthreshÐ¡ÓÚ½ÓÊÕ»º´æÊ£Óà¿Õ¼äµÄ3/4£¬
	//Í¬Ê±tcp_memory_pressureÃ»ÓÐ±»ÖÃÎ»(¼´½ÓÊÕ»º´æÖÐµÄÊý¾ÝÁ¿Ã»ÓÐÌ«´ó)¡£ tcp_grow_windowÖÐ¶ÔÐÂÊÕµ½µÄskbµÄ³¤¶È»¹ÓÐÒ»Ð©ÏÞÖÆ£¬²¢²»×ÜÊÇÔö³¤rcv_ssthreshµÄÖµ*/ 
	if (skb->len >= 128)
		tcp_grow_window(sk, skb);
}

static u32 tcp_rto_min(struct sock *sk)
{
	struct dst_entry *dst = __sk_dst_get(sk);
	u32 rto_min = TCP_RTO_MIN;

	if (dst && dst_metric_locked(dst, RTAX_RTO_MIN))
		rto_min = dst->metrics[RTAX_RTO_MIN-1];
	return rto_min;
}

/* Called to compute a smoothed rtt estimate. The data fed to this
 * routine either comes from timestamps, or from segments that were
 * known _not_ to have been retransmitted [see Karn/Partridge
 * Proceedings SIGCOMM 87]. The algorithm is from the SIGCOMM 88
 * piece by Van Jacobson.
 * NOTE: the next three routines used to be one big routine.
 * To save cycles in the RFC 1323 implementation it was better to break
 * it up into three procedures. -- erics
 */
static void tcp_rtt_estimator(struct sock *sk, const __u32 mrtt)
{
	struct tcp_sock *tp = tcp_sk(sk);
	long m = mrtt; /* RTT */

	/*	The following amusing code comes from Jacobson's
	 *	article in SIGCOMM '88.  Note that rtt and mdev
	 *	are scaled versions of rtt and mean deviation.
	 *	This is designed to be as fast as possible
	 *	m stands for "measurement".
	 *
	 *	On a 1990 paper the rto value is changed to:
	 *	RTO = rtt + 4 * mdev
	 *
	 * Funny. This algorithm seems to be very broken.
	 * These formulae increase RTO, when it should be decreased, increase
	 * too slowly, when it should be increased quickly, decrease too quickly
	 * etc. I guess in BSD RTO takes ONE value, so that it is absolutely
	 * does not matter how to _calculate_ it. Seems, it was trap
	 * that VJ failed to avoid. 8)
	 */
	if (m == 0)
		m = 1;
	if (tp->srtt != 0) {
		m -= (tp->srtt >> 3);	/* m is now error in rtt est */
		tp->srtt += m;		/* rtt = 7/8 rtt + 1/8 new */
		if (m < 0) {
			m = -m;		/* m is now abs(error) */
			m -= (tp->mdev >> 2);   /* similar update on mdev */
			/* This is similar to one of Eifel findings.
			 * Eifel blocks mdev updates when rtt decreases.
			 * This solution is a bit different: we use finer gain
			 * for mdev in this case (alpha*beta).
			 * Like Eifel it also prevents growth of rto,
			 * but also it limits too fast rto decreases,
			 * happening in pure Eifel.
			 */
			if (m > 0)
				m >>= 3;
		} else {
			m -= (tp->mdev >> 2);   /* similar update on mdev */
		}
		tp->mdev += m;	    	/* mdev = 3/4 mdev + 1/4 new */
		if (tp->mdev > tp->mdev_max) {
			tp->mdev_max = tp->mdev;
			if (tp->mdev_max > tp->rttvar)
				tp->rttvar = tp->mdev_max;
		}
		if (after(tp->snd_una, tp->rtt_seq)) {
			if (tp->mdev_max < tp->rttvar)
				tp->rttvar -= (tp->rttvar-tp->mdev_max)>>2;
			tp->rtt_seq = tp->snd_nxt;
			tp->mdev_max = tcp_rto_min(sk);
		}
	} else {
		/* no previous measure. */
		tp->srtt = m<<3;	/* take the measured time to be rtt */
		tp->mdev = m<<1;	/* make sure rto = 3*rtt */
		tp->mdev_max = tp->rttvar = max(tp->mdev, tcp_rto_min(sk));
		tp->rtt_seq = tp->snd_nxt;
	}
}

/* Calculate rto without backoff.  This is the second half of Van Jacobson's
 * routine referred to above.
 */
static inline void tcp_set_rto(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	/* Old crap is replaced with new one. 8)
	 *
	 * More seriously:
	 * 1. If rtt variance happened to be less 50msec, it is hallucination.
	 *    It cannot be less due to utterly erratic ACK generation made
	 *    at least by solaris and freebsd. "Erratic ACKs" has _nothing_
	 *    to do with delayed acks, because at cwnd>2 true delack timeout
	 *    is invisible. Actually, Linux-2.4 also generates erratic
	 *    ACKs in some circumstances.
	 */
	inet_csk(sk)->icsk_rto = (tp->srtt >> 3) + tp->rttvar;

	/* 2. Fixups made earlier cannot be right.
	 *    If we do not estimate RTO correctly without them,
	 *    all the algo is pure shit and should be replaced
	 *    with correct one. It is exactly, which we pretend to do.
	 */
}

/* NOTE: clamping at TCP_RTO_MIN is not required, current algo
 * guarantees that rto is higher.
 */
static inline void tcp_bound_rto(struct sock *sk)
{
	if (inet_csk(sk)->icsk_rto > TCP_RTO_MAX)
		inet_csk(sk)->icsk_rto = TCP_RTO_MAX;
}

/* Save metrics learned by this TCP session.
   This function is called only, when TCP finishes successfully
   i.e. when it enters TIME-WAIT or goes from LAST-ACK to CLOSE.
 */
void tcp_update_metrics(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);

	if (sysctl_tcp_nometrics_save)
		return;

	dst_confirm(dst);

	if (dst && (dst->flags&DST_HOST)) {
		const struct inet_connection_sock *icsk = inet_csk(sk);
		int m;

		if (icsk->icsk_backoff || !tp->srtt) {
			/* This session failed to estimate rtt. Why?
			 * Probably, no packets returned in time.
			 * Reset our results.
			 */
			if (!(dst_metric_locked(dst, RTAX_RTT)))
				dst->metrics[RTAX_RTT-1] = 0;
			return;
		}

		m = dst_metric(dst, RTAX_RTT) - tp->srtt;

		/* If newly calculated rtt larger than stored one,
		 * store new one. Otherwise, use EWMA. Remember,
		 * rtt overestimation is always better than underestimation.
		 */
		if (!(dst_metric_locked(dst, RTAX_RTT))) {
			if (m <= 0)
				dst->metrics[RTAX_RTT-1] = tp->srtt;
			else
				dst->metrics[RTAX_RTT-1] -= (m>>3);
		}

		if (!(dst_metric_locked(dst, RTAX_RTTVAR))) {
			if (m < 0)
				m = -m;

			/* Scale deviation to rttvar fixed point */
			m >>= 1;
			if (m < tp->mdev)
				m = tp->mdev;

			if (m >= dst_metric(dst, RTAX_RTTVAR))
				dst->metrics[RTAX_RTTVAR-1] = m;
			else
				dst->metrics[RTAX_RTTVAR-1] -=
					(dst->metrics[RTAX_RTTVAR-1] - m)>>2;
		}

		if (tp->snd_ssthresh >= 0xFFFF) {
			/* Slow start still did not finish. */
			if (dst_metric(dst, RTAX_SSTHRESH) &&
			    !dst_metric_locked(dst, RTAX_SSTHRESH) &&
			    (tp->snd_cwnd >> 1) > dst_metric(dst, RTAX_SSTHRESH))
				dst->metrics[RTAX_SSTHRESH-1] = tp->snd_cwnd >> 1;
			if (!dst_metric_locked(dst, RTAX_CWND) &&
			    tp->snd_cwnd > dst_metric(dst, RTAX_CWND))
				dst->metrics[RTAX_CWND-1] = tp->snd_cwnd;
		} else if (tp->snd_cwnd > tp->snd_ssthresh &&
			   icsk->icsk_ca_state == TCP_CA_Open) {
			/* Cong. avoidance phase, cwnd is reliable. */
			if (!dst_metric_locked(dst, RTAX_SSTHRESH))
				dst->metrics[RTAX_SSTHRESH-1] =
					max(tp->snd_cwnd >> 1, tp->snd_ssthresh);
			if (!dst_metric_locked(dst, RTAX_CWND))
				dst->metrics[RTAX_CWND-1] = (dst->metrics[RTAX_CWND-1] + tp->snd_cwnd) >> 1;
		} else {
			/* Else slow start did not finish, cwnd is non-sense,
			   ssthresh may be also invalid.
			 */
			if (!dst_metric_locked(dst, RTAX_CWND))
				dst->metrics[RTAX_CWND-1] = (dst->metrics[RTAX_CWND-1] + tp->snd_ssthresh) >> 1;
			if (dst->metrics[RTAX_SSTHRESH-1] &&
			    !dst_metric_locked(dst, RTAX_SSTHRESH) &&
			    tp->snd_ssthresh > dst->metrics[RTAX_SSTHRESH-1])
				dst->metrics[RTAX_SSTHRESH-1] = tp->snd_ssthresh;
		}

		if (!dst_metric_locked(dst, RTAX_REORDERING)) 
		{
			if (dst->metrics[RTAX_REORDERING-1] < tp->reordering && tp->reordering != sysctl_tcp_reordering)
				dst->metrics[RTAX_REORDERING-1] = tp->reordering;
		}
	}
}

/* Numbers are taken from RFC3390.
 *
 * John Heffner states:
 *
 *	The RFC specifies a window of no more than 4380 bytes
 *	unless 2*MSS > 4380.  Reading the pseudocode in the RFC
 *	is a bit misleading because they use a clamp at 4380 bytes
 *	rather than use a multiplier in the relevant range.
 */
__u32 tcp_init_cwnd(struct tcp_sock *tp, struct dst_entry *dst)
{
	__u32 cwnd = (dst ? dst_metric(dst, RTAX_INITCWND) : 0);

	if (!cwnd) {
		if (tp->mss_cache > 1460)
			cwnd = 2;
		else
			cwnd = (tp->mss_cache > 1095) ? 3 : 4;
	}
	return min_t(__u32, cwnd, tp->snd_cwnd_clamp);
}

/* Set slow start threshold and cwnd not falling to slow start */
//enter into the TCP_CA_CWR state 
void tcp_enter_cwr(struct sock *sk, const int set_ssthresh)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);

	tp->prior_ssthresh = 0;
	tp->bytes_acked = 0;
	//we enter into the TCP_CA_CWR state,in case we are in an open state or a disorder state but not in any other TCP state
	if (icsk->icsk_ca_state < TCP_CA_CWR) 
	{
		//tp->undo_marker is not set because we are sure that we are not retransmitting anything in this state
		//(tp->undo_marker should be set to undo from the congestion state; refer to tcp_may_undo()).
		tp->undo_marker = 0;
		if (set_ssthresh)
			tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
		//the send congestion window is reduced to a value so that we should be able to send a maximum of one segment.
		//we adjust the congestion window to a minimum of current congestion window and (packets
		//in flight + 1), which means that at the most we can send only one new segment until
		//segments in flight are ACKed.
		tp->snd_cwnd = min(tp->snd_cwnd, tcp_packets_in_flight(tp) + 1U);
		tp->snd_cwnd_cnt = 0;
		tp->high_seq = tp->snd_nxt;
		tp->snd_cwnd_stamp = tcp_time_stamp;
		TCP_ECN_queue_cwr(tp);

		tcp_set_ca_state(sk, TCP_CA_CWR);
	}
}

/*
 * Packet counting of FACK is based on in-order assumptions, therefore TCP
 * disables it when reordering is detected
 */
static void tcp_disable_fack(struct tcp_sock *tp)
{
	tp->rx_opt.sack_ok &= ~2;
}

/* Take a notice that peer is sending D-SACKs */
static void tcp_dsack_seen(struct tcp_sock *tp)
{
	tp->rx_opt.sack_ok |= 4;
}

/* Initialize metrics on socket. */

static void tcp_init_metrics(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);

	if (dst == NULL)
		goto reset;

	dst_confirm(dst);

	if (dst_metric_locked(dst, RTAX_CWND))
		tp->snd_cwnd_clamp = dst_metric(dst, RTAX_CWND);
	if (dst_metric(dst, RTAX_SSTHRESH)) {
		tp->snd_ssthresh = dst_metric(dst, RTAX_SSTHRESH);
		if (tp->snd_ssthresh > tp->snd_cwnd_clamp)
			tp->snd_ssthresh = tp->snd_cwnd_clamp;
	}
	if (dst_metric(dst, RTAX_REORDERING) && tp->reordering != dst_metric(dst, RTAX_REORDERING))
	{
		tcp_disable_fack(tp);
		tp->reordering = dst_metric(dst, RTAX_REORDERING);
	}

	if (dst_metric(dst, RTAX_RTT) == 0)
		goto reset;

	if (!tp->srtt && dst_metric(dst, RTAX_RTT) < (TCP_TIMEOUT_INIT << 3))
		goto reset;

	/* Initial rtt is determined from SYN,SYN-ACK.
	 * The segment is small and rtt may appear much
	 * less than real one. Use per-dst memory
	 * to make it more realistic.
	 *
	 * A bit of theory. RTT is time passed after "normal" sized packet
	 * is sent until it is ACKed. In normal circumstances sending small
	 * packets force peer to delay ACKs and calculation is correct too.
	 * The algorithm is adaptive and, provided we follow specs, it
	 * NEVER underestimate RTT. BUT! If peer tries to make some clever
	 * tricks sort of "quick acks" for time long enough to decrease RTT
	 * to low value, and then abruptly stops to do it and starts to delay
	 * ACKs, wait for troubles.
	 */
	if (dst_metric(dst, RTAX_RTT) > tp->srtt) {
		tp->srtt = dst_metric(dst, RTAX_RTT);
		tp->rtt_seq = tp->snd_nxt;
	}
	if (dst_metric(dst, RTAX_RTTVAR) > tp->mdev) {
		tp->mdev = dst_metric(dst, RTAX_RTTVAR);
		tp->mdev_max = tp->rttvar = max(tp->mdev, tcp_rto_min(sk));
	}
	tcp_set_rto(sk);
	tcp_bound_rto(sk);
	if (inet_csk(sk)->icsk_rto < TCP_TIMEOUT_INIT && !tp->rx_opt.saw_tstamp)
		goto reset;
	tp->snd_cwnd = tcp_init_cwnd(tp, dst);
	tp->snd_cwnd_stamp = tcp_time_stamp;
	return;

reset:
	/* Play conservative. If timestamps are not
	 * supported, TCP will fail to recalculate correct
	 * rtt, if initial rto is too small. FORGET ALL AND RESET!
	 */
	if (!tp->rx_opt.saw_tstamp && tp->srtt) {
		tp->srtt = 0;
		tp->mdev = tp->mdev_max = tp->rttvar = TCP_TIMEOUT_INIT;
		inet_csk(sk)->icsk_rto = TCP_TIMEOUT_INIT;
	}
}

static void tcp_update_reordering(struct sock *sk, const int metric, const int ts)
{
	struct tcp_sock *tp = tcp_sk(sk);
	if (metric > tp->reordering) 
	{
		tp->reordering = min(TCP_MAX_REORDERING, metric);

		/* This exciting event is worth to be remembered. 8) */
		if (ts)
			NET_INC_STATS_BH(LINUX_MIB_TCPTSREORDER);
		else if (tcp_is_reno(tp))
			NET_INC_STATS_BH(LINUX_MIB_TCPRENOREORDER);
		else if (tcp_is_fack(tp))
			NET_INC_STATS_BH(LINUX_MIB_TCPFACKREORDER);
		else
			NET_INC_STATS_BH(LINUX_MIB_TCPSACKREORDER);
#if FASTRETRANS_DEBUG > 1
		printk(KERN_DEBUG "Disorder%d %d %u f%u s%u rr%d\n",
		       tp->rx_opt.sack_ok, inet_csk(sk)->icsk_ca_state,
		       tp->reordering,
		       tp->fackets_out,
		       tp->sacked_out,
		       tp->undo_marker ? tp->undo_retrans : 0);
#endif
		tcp_disable_fack(tp);
	}
}

/* This procedure tags the retransmission queue when SACKs arrive.
 *
 * We have three tag bits: SACKED(S), RETRANS(R) and LOST(L).
 * Packets in queue with these bits set are counted in variables
 * sacked_out, retrans_out and lost_out, correspondingly.
 *
 * Valid combinations are:
 * Tag  InFlight	Description
 * 0	1		- orig segment is in flight.
 * S	0		- nothing flies, orig reached receiver.
 * L	0		- nothing flies, orig lost by net.
 * R	2		- both orig and retransmit are in flight.
 * L|R	1		- orig is lost, retransmit is in flight.
 * S|R  1		- orig reached receiver, retrans is still in flight.
 * (L|S|R is logically valid, it could occur when L|R is sacked,
 *  but it is equivalent to plain S and code short-curcuits it to S.
 *  L|S is logically invalid, it would mean -1 packet in flight 8))
 *
 * These 6 states form finite state machine, controlled by the following events:
 * 1. New ACK (+SACK) arrives. (tcp_sacktag_write_queue())
 * 2. Retransmission. (tcp_retransmit_skb(), tcp_xmit_retransmit_queue())
 * 3. Loss detection event of one of three flavors:
 *	A. Scoreboard estimator decided the packet is lost.
 *	   A'. Reno "three dupacks" marks head of queue lost.
 *	   A''. Its FACK modfication, head until snd.fack is lost.
 *	B. SACK arrives sacking data transmitted after never retransmitted
 *	   hole was sent out.
 *	C. SACK arrives sacking SND.NXT at the moment, when the
 *	   segment was retransmitted.
 * 4. D-SACK added new rule: D-SACK changes any tag to S.
 *
 * It is pleasant to note, that state diagram turns out to be commutative,
 * so that we are allowed not to be bothered by order of our actions,
 * when multiple events arrive simultaneously. (see the function below).
 *
 * Reordering detection.
 * --------------------
 * Reordering metric is maximal distance, which a packet can be displaced
 * in packet stream. With SACKs we can estimate it:
 *
 * 1. SACK fills old hole and the corresponding segment was not
 *    ever retransmitted -> reordering. Alas, we cannot use it
 *    when segment was retransmitted.
 * 2. The last flaw is solved with D-SACK. D-SACK arrives
 *    for retransmitted and already SACKed segment -> reordering..
 * Both of these heuristics are not used in Loss state, when we cannot
 * account for retransmits accurately.
 *
 * SACK block validation.
 * ----------------------
 *
 * SACK block range validation checks that the received SACK block fits to
 * the expected sequence limits, i.e., it is between SND.UNA and SND.NXT.
 * Note that SND.UNA is not included to the range though being valid because
 * it means that the receiver is rather inconsistent with itself reporting
 * SACK reneging when it should advance SND.UNA. Such SACK block this is
 * perfectly valid, however, in light of RFC2018 which explicitly states
 * that "SACK block MUST reflect the newest segment.  Even if the newest
 * segment is going to be discarded ...", not that it looks very clever
 * in case of head skb. Due to potentional receiver driven attacks, we
 * choose to avoid immediate execution of a walk in write queue due to
 * reneging and defer head skb's loss recovery to standard loss recovery
 * procedure that will eventually trigger (nothing forbids us doing this).
 *
 * Implements also blockage to start_seq wrap-around. Problem lies in the
 * fact that though start_seq (s) is before end_seq (i.e., not reversed),
 * there's no guarantee that it will be before snd_nxt (n). The problem
 * happens when start_seq resides between end_seq wrap (e_w) and snd_nxt
 * wrap (s_w):
 *
 *         <- outs wnd ->                          <- wrapzone ->
 *         u     e      n                         u_w   e_w  s n_w
 *         |     |      |                          |     |   |  |
 * |<------------+------+----- TCP seqno space --------------+---------->|
 * ...-- <2^31 ->|                                           |<--------...
 * ...---- >2^31 ------>|                                    |<--------...
 *
 * Current code wouldn't be vulnerable but it's better still to discard such
 * crazy SACK blocks. Doing this check for start_seq alone closes somewhat
 * similar case (end_seq after snd_nxt wrap) as earlier reversed check in
 * snd_nxt wrap -> snd_una region will then become "well defined", i.e.,
 * equal to the ideal case (infinite seqno space without wrap caused issues).
 *
 * With D-SACK the lower bound is extended to cover sequence space below
 * SND.UNA down to undo_marker, which is the last point of interest. Yet
 * again, D-SACK block must not to go across snd_una (for the same reason as
 * for the normal SACK blocks, explained above). But there all simplicity
 * ends, TCP might receive valid D-SACKs below that. As long as they reside
 * fully below undo_marker they do not affect behavior in anyway and can
 * therefore be safely ignored. In rare cases (which are more or less
 * theoretical ones), the D-SACK will nicely cross that boundary due to skb
 * fragmentation and packet reordering past skb's retransmission. To consider
 * them correctly, the acceptable range must be extended even more though
 * the exact amount is rather hard to quantify. However, tp->max_window can
 * be used as an exaggerated estimate.
 */
static int tcp_is_sackblock_valid(struct tcp_sock *tp, int is_dsack, u32 start_seq, u32 end_seq)
{
	/* Too far in future, or reversed (interpretation is ambiguous) */
	if (after(end_seq, tp->snd_nxt) || !before(start_seq, end_seq))
		return 0;

	/* Nasty start_seq wrap-around check (see comments above) */
	if (!before(start_seq, tp->snd_nxt))
		return 0;

	/* In outstanding window? ...This is valid exit for D-SACKs too.
	 * start_seq == snd_una is non-sensical (see comments above)
	 */
	if (after(start_seq, tp->snd_una))
		return 1;

	if (!is_dsack || !tp->undo_marker)
		return 0;

	/* ...Then it's D-SACK, and must reside below snd_una completely */
	if (!after(end_seq, tp->snd_una))
		return 0;

	if (!before(start_seq, tp->undo_marker))
		return 1;

	/* Too old */
	if (!after(end_seq, tp->undo_marker))
		return 0;

	/* Undo_marker boundary crossing (overestimates a lot). Known already:
	 *   start_seq < undo_marker and end_seq >= undo_marker.
	 */
	return !before(start_seq, end_seq - tp->max_window);
}

/* Check for lost retransmit. This superb idea is borrowed from "ratehalving".
 * Event "C". Later note: FACK people cheated me again 8), we have to account
 * for reordering! Ugly, but should help.
 *
 * Search retransmitted skbs from write_queue that were sent when snd_nxt was
 * less than what is now known to be received by the other end (derived from
 * SACK blocks by the caller). Also calculate the lowest snd_nxt among the
 * remaining retransmitted skbs to avoid some costly processing per ACKs.
 */
static int tcp_mark_lost_retrans(struct sock *sk, u32 received_upto)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int flag = 0;
	int cnt = 0;
	u32 new_low_seq = tp->snd_nxt;

	tcp_for_write_queue(skb, sk) 
	{
		u32 ack_seq = TCP_SKB_CB(skb)->ack_seq;

		if (skb == tcp_send_head(sk))
			break;
		
		if (cnt == tp->retrans_out)
			break;
		
		if (!after(TCP_SKB_CB(skb)->end_seq, tp->snd_una))
			continue;

		if (!(TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS))
			continue;

		if (after(received_upto, ack_seq) &&  (tcp_is_fack(tp) || !before(received_upto, ack_seq + tp->reordering * tp->mss_cache)))
		{
			TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_RETRANS;
			tp->retrans_out -= tcp_skb_pcount(skb);

			/* clear lost hint */
			tp->retransmit_skb_hint = NULL;

			if (!(TCP_SKB_CB(skb)->sacked & (TCPCB_LOST|TCPCB_SACKED_ACKED))) {
				tp->lost_out += tcp_skb_pcount(skb);
				TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
				flag |= FLAG_DATA_SACKED;
				NET_INC_STATS_BH(LINUX_MIB_TCPLOSTRETRANSMIT);
			}
		} else {
			if (before(ack_seq, new_low_seq))
				new_low_seq = ack_seq;
			cnt += tcp_skb_pcount(skb);
		}
	}

	if (tp->retrans_out)
		tp->lost_retrans_low = new_low_seq;

	return flag;
}

static int tcp_check_dsack(struct tcp_sock *tp, struct sk_buff *ack_skb, struct tcp_sack_block_wire *sp, int num_sacks, u32 prior_snd_una)
{
	u32 start_seq_0 = ntohl(get_unaligned(&sp[0].start_seq));
	u32 end_seq_0 = ntohl(get_unaligned(&sp[0].end_seq));
	int dup_sack = 0;

	//Èç¹ûµÚÒ»¸öSACK¿éµÄÆðÊ¼ÐòºÅÐ¡ÓÚËüµÄÈ·ÈÏÐòºÅ£¬ËµÃ÷´ËSACK¿é°üº¬ÁËÈ·ÈÏ¹ýµÄÊý¾Ý
	if (before(start_seq_0, TCP_SKB_CB(ack_skb)->ack_seq))
	{
		dup_sack = 1;
		tcp_dsack_seen(tp);
		NET_INC_STATS_BH(LINUX_MIB_TCPDSACKRECV);
	} 
	else if (num_sacks > 1) 
	{
		u32 end_seq_1 = ntohl(get_unaligned(&sp[1].end_seq));
		u32 start_seq_1 = ntohl(get_unaligned(&sp[1].start_seq));
		
		//Èç¹ûµÚÒ»¸öSACK¿é°üº¬ÔÚµÚ¶þ¸öSACK¿éÖÐ£¬Ò²ËµÃ÷µÚÒ»¸öSACK¿éÊÇÖØ¸´µÄ£¬¼´DSACK
		if (!after(end_seq_0, end_seq_1) && !before(start_seq_0, start_seq_1)) 
		{
			dup_sack = 1;
			tcp_dsack_seen(tp);
			NET_INC_STATS_BH(LINUX_MIB_TCPDSACKOFORECV);
		}
	}

	//´¦ÀíD-SACKÖÐ½ÓÊÕÕßÊÕµ½ÖØ¸´ÇÒÒÑ±»È·ÈÏµÄÊý¾ÝµÄÇé¿ö(undo_marker µ½ prior_snd_unaÖ®¼äµÄÊý¾Ý)
	//we check if the D-SACK is generated for the data that are already ACKed
	//because the retransmitted segment reached before the original segment was ACKed
	//or vice versa. In this case the end sequence of the SACK block should be within
	//the ACKed sequence prior to arrival of this segment, and the end sequence should
	//also be after the tp->undo_marker
	if (dup_sack && !after(end_seq_0, prior_snd_una) && after(end_seq_0, tp->undo_marker))
	{
		//ËµÃ÷½øÐÐÁË²»±ØÒªµÄÖØ´«, ÍøÂçÓµÈû¿ÉÄÜ²»ÑÏÖØ£¬¼õÉÙÖØ´«undo_retrans¼ÆÊý£¬
		//We will decrement tp->undo_retrans by 1 in such a case because that D-SACK is generated 
		//because of retransmission of a segment that was considered lost when we entered the recovery phase. 
		//But the segment reached the receiver later because of reordering.
		tp->undo_retrans--;
	}

	return dup_sack;
}

/* Check if skb is fully within the SACK block. In presence of GSO skbs,
 * the incoming SACK may not exactly match but we can find smaller MSS
 * aligned portion of it that matches. Therefore we might need to fragment
 * which may fail and creates some hassle (caller must handle error case
 * returns).
 */
//seq        end_seq
//|             |seq       end_seq
//|             ||            |seq            end_seq
//|        |    ||            ||      |         |
//<------a------><------b-----><--------c------->  //ÖØ´«¶ÓÁÐÖÐµÄ¶Îa£¬b£¬c
//         |<--------sack block------>|
//      start_seq                  end_seq
static int tcp_match_skb_to_sack(struct sock *sk, struct sk_buff *skb, u32 start_seq, u32 end_seq)
{
	int in_sack, err;
	unsigned int pkt_len;
	
	//¼ì²âµ±Ç°µÄ¶ÎÊÇ·ñÕû¸ö´¦ÓÚ¸ÃSACK¿éÖÐ(¶Îb)£¬Èç¹ûÊÇ£¬ÔòËµÃ÷µ±Ç°µÄ¶Î½ÓÊÕ·½ÒÑÍêÈ«½ÓÊÕµ½£¬ÎÞÂÛÊÇTSO¶Î»¹ÊÇÆÕÍ¨µÄ¶Î
	in_sack = !after(start_seq, TCP_SKB_CB(skb)->seq) && !before(end_seq, TCP_SKB_CB(skb)->end_seq);

	//Èç¹ûµ±Ç°¶ÎÊÇTSO¶ÎÇÒ²»Õû¸ö´¦ÓÚSACK¿éÖÐÇÒÓëSACK¿éÓÐ½»¼¯(Ö»ÓÐ¶Îa£¬¶ÎcÁ½ÖÖÇé¿ö)£¬
	//ÔòËµÃ÷½ÓÊÕ·½ÊÕµ½ÁË²¿·ÖÊý¾Ý£¬ÄÇÐ©ÒÑ½ÓÊÜµÄ¶Î¾Í²»ÐèÒªÔÙ´«ÁË£¬Òò´Ë°ÑTSO¶Î·Ö¸î³ÉÆÕÍ¨µÄ¶Î¡£
	if (tcp_skb_pcount(skb) > 1 && !in_sack && after(TCP_SKB_CB(skb)->end_seq, start_seq))
	{
	
		//Èç¹ûSACK¿éµÄstart_seqÔÚ¶ÎµÄseqÖ®ºó£¬´Ó¶Îa¿´³öseqºÍSACK¿ìµÄstart_seqÖ®¼äµÄÊý¾Ý½ÓÊÕ·½Ã»ÓÐ½ÓÊÕµ½£¬Òò´ËÊ¹ÓÃstart_seq - seq×÷ÎªÊÖ¶¯TSO·Ö¶ÎµÄ¶Î³¤
		//Èç¹û¶ÎµÄseqÔÚSACK¿éµÄstart_seqÖ®ºó£¬´Ó¶Îc¿´³öseqºÍSACK¿éµÄend_seqÖ®¼äµÄÊý¾Ý½ÓÊÕ·½ÒÑ¾­½ÓÊÕµ½£¬Òò´ËÊ¹ÓÃend_seq - seq×÷ÎªÊÖ¶¯TSO·Ö¶ÎµÄ¶Î³¤
		in_sack = !after(start_seq, TCP_SKB_CB(skb)->seq);
		if (!in_sack)
			pkt_len = start_seq - TCP_SKB_CB(skb)->seq;
		else
			pkt_len = end_seq - TCP_SKB_CB(skb)->seq;
		//µ÷ÓÃtcp_fragment()£¬ÊÖ¶¯¶ÔTSO¶Î½øÐÐ·Ö¶Î
		err = tcp_fragment(sk, skb, pkt_len, skb_shinfo(skb)->gso_size);
		if (err < 0)
			return err;
	}

	return in_sack;
}

//  prior_snd_una      snd_una     snd_nxt
//--------|--------------|----------|-------
//´¦Àísnd_unaµ½snd_nxtÖ®¼ä±»È·ÈÏµÄ±¨ÎÄ¶Î
//ack_skb -- ÐÂÊÕµ½µÄACK¶Î
//prior_snd_una -- ¸ù¾Ý¸ÃACK¶Î¸üÐÂ·¢ËÍ´°¿ÚÇ°µÄsnd_una


//There may be D - SACK blocks or SACK blocks which may have SACKed new data.
//We need to update the state of each individual segment in the retransmit queue. 
//We may have a new SACK block that has selectively ACKed a never retransmitted
//segment or a retransmitted segment or lost segment.
static int
tcp_sacktag_write_queue(struct sock *sk, struct sk_buff *ack_skb, u32 prior_snd_una)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned char *ptr = (skb_transport_header(ack_skb) + TCP_SKB_CB(ack_skb)->sacked); //sackÑ¡ÏîµÄÆðÊ¼µØÖ·, TCP_SKB_CB(ack_skb)->sackedÎªsackÑ¡ÏîÔÚTCPÊ×²¿µÄÆ«ÒÆ
	struct tcp_sack_block_wire *sp = (struct tcp_sack_block_wire *)(ptr+2);  //sack blockµÄÆðÊ¼µØÖ·
	struct sk_buff *cached_skb;
	int num_sacks = (ptr[1] - TCPOLEN_SACK_BASE)>>3; //sack blockµÄ¸öÊý
	/* ÂÒÐòµÄÆðÊ¼°üÎ»ÖÃ£¬Ò»¿ªÊ¼ÉèÎª×î´ó */
	//'reord' is calculated as segment lowest in the sequential order SACKed/
	//ACKed so far which is recorded whenever we receive D-SACK or receive SACK
	//for the hole which was never retransmitted.
	int reord = tp->packets_out;   //ÓÃÓÚ¼ÆËã±¾´ÎµÄfackets_out£¬ÓÉÓÚfackets_out±Ø¶¨Ð¡ÓÚ»òµÈÓÚtp->packets_out£¬Òò´Ë³õÊ¼»¯Îªtp->packets_out
	int prior_fackets;		//ÉÏ´ÎµÄfackets_out
	u32 highest_sack_end_seq = tp->lost_retrans_low;
	int flag = 0;
	int found_dup_sack = 0;
	int cached_fack_count;
	int i;
	int first_sack_index;
	int force_one_sack;

	//tp->sacked_out is zero which means that none of the segment were SACKed out prior to arrival of this segment
	if (!tp->sacked_out)			//Èç¹ûÖ®Ç°Ã»ÓÐSACKedµÄÊý¾Ý£¬ ÕâÊÇÎÒÃÇµÚÒ»´Î»ñÈ¡µ½sackÑ¡Ïî
	{
		//we initialize FORWARD ACKed (tp->fackets_out) segment count to 0
		//The reason is that forward ACKed segments are calculated based on the latest SACK information
		if (WARN_ON(tp->fackets_out))
			tp->fackets_out = 0;    	
		tp->highest_sack = tp->snd_una;	// tp->highest_sackÖÃÎª·¢ËÍ¶ÓÁÐµÄµÚÒ»¸öÊý¾Ý°ü£¬ÒòÎªÃ»ÓÐSACK¿é
	}
	prior_fackets = tp->fackets_out;

	//¼ì²éµÚÒ»¸öSACK¿éÊÇ·ñÎªDSACK 
	found_dup_sack = tcp_check_dsack(tp, ack_skb, sp, num_sacks, prior_snd_una);
	if (found_dup_sack)
		flag |= FLAG_DSACKING_ACK;

	/* Eliminate too old ACKs, but take into account more or less fresh ones, they can  contain valid SACK info. */
	//Èç¹ûÊÕµ½µÄACK¶ÎµÄÈ·ÈÏÐòºÅÊÇÒ»¸ö´°¿ÚÒÔÇ°µÄ£¬ÔòËµÃ÷ACKÌ«³Â¾ÉÁË£¬²»ÐèÒª´¦Àí£¬Ö±½Ó·µ»Ø
	//we check if we got ACK for too old data. that is, ACK acknowledges one window of old data. 
	//This ACK segment might have got stuck in the network for sometime before it reached before 
	//we got ACK for the latest data that are received in sequence. In this case we discard the SACK 
	//because the SACK information may be too old to consider and return.
	if (before(TCP_SKB_CB(ack_skb)->ack_seq, prior_snd_una - tp->max_window))
		return 0;

	//Èç¹ûÎÒÃÇ²¢Ã»ÓÐ·¢ËÍÊý¾Ýµ½ÍøÂçÖÐ£¬´íÎó
	if (!tp->packets_out)
		goto out;

	/* SACK fastpath:
	 * if the only SACK change is the increase of the end_seq of
	 * the first block then only apply that SACK block
	 * and use retrans queue hinting otherwise slowpath */  

	//½«SACK¿é´æ´¢µ½recv_sack_cacheÖÐ£¬Í¬Ê±È·¶¨¿ìËÙÂ·¾¶»¹ÊÇÂýËÙÂ·¾¶´¦Àí
	//Èç¹ûÖ»ÓÐµÚÒ»¸öSACK¿éµÄend_seq³öÏÖÁËÔö¼Ó£¬ÔòÖ´ÐÐ¿ìËÙÂ·¾¶£¬´ÓÉÏ´Î´¦ÀíSACK½áÊø´¦¿ªÊ¼chu
	//·ñÔòÖ´ÐÐÂýËÙÂ·¾¶£¬´ÓÖØ´«¶ÓÁÐÍ·¿ªÊ¼
	force_one_sack = 1;
	for (i = 0; i < num_sacks; i++) 
	{
		__be32 start_seq = sp[i].start_seq;
		__be32 end_seq = sp[i].end_seq;

		if (i == 0)
		{
			if (tp->recv_sack_cache[i].start_seq != start_seq)
				force_one_sack = 0;
		} 
		else 
		{
			if ((tp->recv_sack_cache[i].start_seq != start_seq) || (tp->recv_sack_cache[i].end_seq != end_seq))
				force_one_sack = 0;
		}
		tp->recv_sack_cache[i].start_seq = start_seq;
		tp->recv_sack_cache[i].end_seq = end_seq;
	}
	/* Clear the rest of the cache sack blocks so they won't match mistakenly. */
	for (; i < ARRAY_SIZE(tp->recv_sack_cache); i++) 
	{
		tp->recv_sack_cache[i].start_seq = 0;
		tp->recv_sack_cache[i].end_seq = 0;
	}

	first_sack_index = 0;
	
	if (force_one_sack)
	{
		//Ö´ÐÐµÄÊÇ¿ìËÙÂ·¾¶£¬ÔòÉèÖÃSACK¿éÊýÎª1£¬ ÒòÎª¿ìËÙÂ·¾¶Ê±Ö»ÓÐµÚÒ»¸ö¿éÓÐ±ä»¯£¬´¦ÀíµÚÒ»¸ö¿é¼´¿É
		num_sacks = 1;	
	}
	else 
	{
		//Ö´ÐÐÂýËÙÂ·¾¶
		int j;
		
		//Çå³ý¿ìËÙÂ·¾¶´¦ÀíµÄ¿ªÊ¼µã(¼´fastpath_skb_hintÖ¸ÏòµÄSKB)
		tp->fastpath_skb_hint = NULL;  

		/* order SACK blocks to allow in order walk of the retrans queue */
		for (i = num_sacks-1; i > 0; i--) 
		{
			for (j = 0; j < i; j++)
			{
				if (after(ntohl(sp[j].start_seq), ntohl(sp[j+1].start_seq)))
				{
					struct tcp_sack_block_wire tmp;

					tmp = sp[j];
					sp[j] = sp[j+1];
					sp[j+1] = tmp;

					/* Track where the first SACK block goes to */
					if (j == first_sack_index)
						first_sack_index = j+1;
				}

			}
		}
	}

	/* Use SACK fastpath hint if valid */
	cached_skb = tp->fastpath_skb_hint;
	cached_fack_count = tp->fastpath_cnt_hint;
	if (!cached_skb)  //¸ù¾Ýtp->fastpath_skb_hintÀ´È·¶¨¿ìËÙÂ·¾¢»¹ÊÇÂýËÙÂ·¾¶´¦Àí
	{
		cached_skb = tcp_write_queue_head(sk);
		cached_fack_count = 0;
	}

	for (i = 0; i < num_sacks; i++) 
	{
		struct sk_buff *skb;
		__u32 start_seq = ntohl(sp->start_seq);
		__u32 end_seq = ntohl(sp->end_seq);
		int fack_count;	//ÓÃÓÚÁÙÊ±¼ÇÂ¼±¾´Î¼ÆËãµÃµ½µÄfackets_out£¬Èç¹û´óÓÚ´«Êä¿ØÖÆ¿éµ±Ç°µÄfackets_outÊ±£¬Ôò¸üÐÂµ½´«Êä¿ØÖÆ¿éÖÐ
		int dup_sack = (found_dup_sack && (i == first_sack_index));  	//if the SACK block under consideration is D-SACK
		int next_dup = (found_dup_sack && (i+1 == first_sack_index));	//µ±Ç°SACKµÄÏÂÒ»¸öSACKÊÇ·ñÎªDSACK¿é

		sp++;

		/* ¼ì²éÕâ¸öSACK¿éÊÇ·ñÎªºÏ·¨µÄ */  
		if (!tcp_is_sackblock_valid(tp, dup_sack, start_seq, end_seq)) 
		{
			if (dup_sack) 
			{
				if (!tp->undo_marker)
					NET_INC_STATS_BH(LINUX_MIB_TCPDSACKIGNOREDNOUNDO);
				else
					NET_INC_STATS_BH(LINUX_MIB_TCPDSACKIGNOREDOLD);
			} 
			else 
			{
				/* Don't count olds caused by ACK reordering */
				if ((TCP_SKB_CB(ack_skb)->ack_seq != tp->snd_una) && !after(end_seq, tp->snd_una))
					continue;
				NET_INC_STATS_BH(LINUX_MIB_TCPSACKDISCARD);
			}
			continue;
		}

		skb = cached_skb;
		fack_count = cached_fack_count;

		/* Event "B" in the comment above. */
		// high_seqÊÇ½øÈëRecovery»òLossÊ±µÄsnd_nxt£¬Èç¹ûhigh_seq±»SACKÁË£¬ÄÇÃ´ºÜ¿ÉÄÜÓÐÊý¾Ý°ü¶ªÊ§ÁË£¬²»È»¾Í¿ÉÒÔACKµôhigh_seq·µ»ØOpenÌ¬ÁË¡£
		//ÕâÀï¿ÉÒÔ¿´µ½Ò²¾ÍÊÇÉÏÃæËùËµµÄÊÂ¼þBµ½´ï
		//Èç¹ûSACK³¬³öÁËÖØ´«¶ÓÁÐµÄÎ²²¿£¬ÔòËµÃ÷ÓÐ¶ÎÒÑ¾­¶ªÊ§£¬ ÐèÒª¼ÓÉÏLOST±ê¼Ç
		//it may happen that the congestion window allows us to transmit more data before we enter the
		//OPEN state. In such a case, we may transmit data with sequence higher than tp->high_seq in recovery state.
		//If we get a SACK that covers tp->high_seq, we consider that some data are lost here. 
		//Otherwise we would have gotten ACK for the entire data transmitted so far, 
		//if SACK blocks are generated because segments got reordered in the network instead of getting lost. 
		//We set a data loss flag in this case and will check later if we actually lost any data or not. 
		if (after(end_seq, tp->high_seq))
			flag |= FLAG_DATA_LOST;

		//´Óskb¿ªÊ¼±éÀúÖØ´«¶ÓÁÐ(´Óprior_snd_una¿ªÊ¼)
		//we traverse the entire retransmit queue for each SACK block. The segments in the retransmit queue may
		//already be tagged. These segments are marked either retransmitted, SACKed, lost, or none of these
		tcp_for_write_queue_from(skb, sk)
		{
			int in_sack = 0;
			u8 sacked;

			if (skb == tcp_send_head(sk))
				break;

			//ÎªÏÂÒ»¸öSACK¿éµÄÆðÊ¼Î»ÖÃ×ö»º´æ
			cached_skb = skb;
			cached_fack_count = fack_count;

			//¼ÇÂ¼Õë¶ÔµÚÒ»¸öSACK¿éÔÚÖØ´«¶ÓÁÐÖÐ´¦ÀíÊ±µÄ×îºóÒ»¸öSKB
			//ÎªÏÂÒ»¸öACKµÄSACKÑ¡ÏîµÄ¿ìËÙÂ·¾¶µÄÆðÊ¼Î»ÖÃ×ö»º´æ
			//ÈôÏÂÒ»¸öACKµÄSACKÑ¡ÏîÂú×ã¿ìËÙÂ·¾¶£¬Ôò´Ó´ÓÕâÀï¶ø²»±Ø´ÓÖØ´«¶ÓÁÐÍ·¿ªÊ¼´¦Àí
			if (i == first_sack_index) 
			{
				tp->fastpath_skb_hint = skb;
				tp->fastpath_cnt_hint = fack_count;
			}

			//The segments in the retransmit queue are arranged in order of increasing start
			//sequence number. So, if we find that the end sequence of the SACK block is below
			//the start sequence of the segment, we just skip through this SACK block and move
			//on to the next SACK block.If not so, the SACK block is covered by at least one of 
			//the segments in the retransmit queue.
			if (!before(TCP_SKB_CB(skb)->seq, end_seq))
				break;

			dup_sack = (found_dup_sack && (i == first_sack_index));

			/* Due to sorting DSACK may reside within this SACK block! */
			if (next_dup) 
			{
				u32 dup_start = ntohl(sp->start_seq);
				u32 dup_end = ntohl(sp->end_seq);

				if (before(TCP_SKB_CB(skb)->seq, dup_end))
				{
					in_sack = tcp_match_skb_to_sack(sk, skb, dup_start, dup_end);
					if (in_sack > 0)
						dup_sack = 1;
				}
			}

			/* DSACK info lost if out-of-mem, try SACK still */
			if (in_sack <= 0)
				in_sack = tcp_match_skb_to_sack(sk, skb, start_seq, end_seq);
			if (unlikely(in_sack < 0))  //error happend
				break;

			sacked = TCP_SKB_CB(skb)->sacked;

			/* Account D-SACK for retransmitted packet. */
			//(dup_sack && in_sack) -- ½ÓÊÕ·½ÒÑ¾­ÖØ¸´ÊÕµ½ÁË¸ÃTCP¶Î
			//(sacked & TCPCB_RETRANS) -- ¸ÃTCP¶Î±»ÖØ´«ÁË
			//after(TCP_SKB_CB(skb)->end_seq, tp->undo_marker) -- 
			//ÔòËµÃ÷½ÓÊÕ·½ÒÑ¾­ÖØ¸´ÊÕµ½ÁË¸ÃTCP¶Î£¬Òò´ËÐèÒª¼õÉÙundo_retrans
			//¸ÃSKBÔÚloss/recovery×´Ì¬±»ÖØ´«£¬½ÓÊÕ·½ÖØ¸´½ÓÊÕµ½ÁË¸ÃSKB£¬ËµÃ÷¸ÃSKBÃ»ÓÐ¶ªÊ§£¬¶øÊÇ±»ÍøÂçÑÓÊ±ÁË£¬Ã»ÓÐ±ØÒª½øÐÐÖØ´«
			//An end sequence of the segment occurring after an undo marker(tp->undo_marker) means that 
			//the segment was retransmitted after TCP entered loss/recovery state.
			if ((dup_sack && in_sack) && (sacked & TCPCB_RETRANS) && after(TCP_SKB_CB(skb)->end_seq, tp->undo_marker))
				tp->undo_retrans--;

			/* The frame is ACKed. */
			//we check if the current segment is ACKed by the received segment(prior_snd_una Óë snd_unaÖ®¼ä)
			if (!after(TCP_SKB_CB(skb)->end_seq, tp->snd_una))
			{
				//we check if this was result of reordering or not
				if (sacked & TCPCB_RETRANS)   
				{
					if ((dup_sack && in_sack) && (sacked & TCPCB_SACKED_ACKED))  //ÅÐ¶ÏÊÇ·ñÂÒÐò
						//We record reordering as a minimum of reorder segments and forward ACKed segments 
						reord = min(fack_count, reord); 
				}

				/* Nothing to do; acked frame is about to be dropped. */
				fack_count += tcp_skb_pcount(skb);
				//Õâ¸öskbÒÑ¾­±»Õý³£È·ÈÏÁË£¬²»ÓÃÔÙ´¦ÀíÁË£¬Ëü¼´½«±»¶ªÆú
				//we continue with the next segment in the retransmit queue. Since a segment is ACKed completely, 
				//we will remove this from the retransmit queue in tcp_clean_rtx_queue().
				continue;
			}

			//We are here because the current segment under examination is not ACKed.

			//Èç¹ûÕâ¸ö°ü²»°üº¬ÔÚSACK¿éÖÐ£¬¼´ÔÚSACK¿éÖ®Íâ£¬Ôò²»ÓÃ¼ÌÐø´¦Àí
			if (!in_sack) 
			{
				fack_count += tcp_skb_pcount(skb);
				continue;
			}

			//Èç¹ûskb»¹Ã»ÓÐ±»±êÖ¾ÎªSACK£¬ÄÇÃ´½øÐÐ´¦Àí 
			if (!(sacked & TCPCB_SACKED_ACKED))   //Ã»ÓÐ±» SACKÈ·ÈÏ¹ý
			{
				if (sacked & TCPCB_SACKED_RETRANS)  /* ÓÐR±êÖ¾£¬±íÊ¾±»ÖØ´«¹ý */  
				{
					/* If the segment is not tagged as lost,
					 * we do not clear RETRANS, believing
					 * that retransmission is still in flight.
					 */
					//  * Èç¹ûÖ®Ç°µÄ±êÖ¾ÊÇ£ºL | R£¬ÄÇÃ´ºÃ£¬ÏÖÔÚÊÕµ½°üÁË£¬¿ÉÒÔÇå³ýRºÍL¡£ 
                    //    * Èç¹ûÖ®Ç°µÄ±êÖ¾ÊÇ£ºR£¬ÄÇÃ´ÈÏÎªÏÖÔÚÊÕµ½µÄÊÇorig£¬ÖØ´«°ü»¹ÔÚÂ·ÉÏ£¬ËùÒÔ²»ÓÃ¸É»î£º£© 
					if (sacked & TCPCB_LOST)
					{
						//Èç¹ûSACKÈ·ÈÏµÄÊÇ¶ªÊ§²¢¾­¹ýÖØ´«µÄ¶Î£¬¶ø´Ë´Î½ø¹ýÁËSACKÈ·ÈÏ£¬ËµÃ÷¸Ã¶ÎÃ»ÓÐ¶ªÊ§£¬Òò´ËÐèÒªÈ¥³ýTCPCB_LOSTºÍTCPCB_SACKED_RETRANS±ê¼Ç£¬Í¬Ê±µ÷Õûlost_outºÍretrans_out
					
						//L|R   - orig is lost, retransmit is in flight.
						TCP_SKB_CB(skb)->sacked &= ~(TCPCB_LOST|TCPCB_SACKED_RETRANS);  /* È¡ÏûLºÍR±êÖ¾ */ 
						tp->lost_out -= tcp_skb_pcount(skb);  /* ¸üÐÂLOST°ü¸öÊý */ 
						tp->retrans_out -= tcp_skb_pcount(skb);  /* ¸üÐÂRETRANS°ü¸öÊý */ 

						/* clear lost hint */
						tp->retransmit_skb_hint = NULL;
					}
				} 
				else 
				{
					if (!(sacked & TCPCB_RETRANS))
					{
						/* New sack for not retransmitted frame,
						 * which was in hole. It is reordering.
						 */
						//we try to check here that the current segment is lower in order (fack_count) than 
						//the previously highest-order SACKed segment (tp->facked_out).
						if (fack_count < prior_fackets)  //Èç¹ûÒ»¸ö°üÂäÔÚhighest_sackÖ®Ç°£¬Ëü¼´Ã»±»SACK¹ý£¬Ò²²»ÊÇÖØ´«µÄ£¬ÄÇÃ´ Ëü¿Ï¶¨ÊÇÂÒÐòÁË£¬µ½ÏÖÔÚ²Å±»SACK¡£ 
							reord = min(fack_count, reord);  //Â¼ÂÒÐòµÄÆðÊ¼

						/* SACK enhanced F-RTO (RFC4138; Appendix B) */
						if (!after(TCP_SKB_CB(skb)->end_seq, tp->frto_highmark))
							flag |= FLAG_ONLY_ORIG_SACKED;
					}

					if (sacked & TCPCB_LOST)   /* Èç¹ûÓÐL±êÖ¾ */  
					{
						TCP_SKB_CB(skb)->sacked &= ~TCPCB_LOST;  /* Çå³ýL±êÖ¾ */  
						tp->lost_out -= tcp_skb_pcount(skb);  /* ¸üÐÂlost_out */  

						/* clear lost hint */
						tp->retransmit_skb_hint = NULL;
					}
				}

				TCP_SKB_CB(skb)->sacked |= TCPCB_SACKED_ACKED;  /* ´òÉÏS±êÖ¾ */
				flag |= FLAG_DATA_SACKED;
				tp->sacked_out += tcp_skb_pcount(skb);

				fack_count += tcp_skb_pcount(skb);
				if (fack_count > tp->fackets_out)
					tp->fackets_out = fack_count;

				if (after(TCP_SKB_CB(skb)->seq, tp->highest_sack)) 
				{
					tp->highest_sack = TCP_SKB_CB(skb)->seq;
					highest_sack_end_seq = TCP_SKB_CB(skb)->end_seq;
				}
			} 
			else   //±»SACKÈ·ÈÏ¹ý  /* ÒÑ¾­ÓÐS±êÖ¾ */  
			{
				if (dup_sack && (sacked & TCPCB_RETRANS)) //Èç¹ûÖ®Ç°ÊÇR|S±êÖ¾£¬ÇÒÕâ¸ö°ü±»DSACKÁË£¬ËµÃ÷ÊÇÂÒÐò
					reord = min(fack_count, reord);

				fack_count += tcp_skb_pcount(skb);
			}

			/* D-SACK. We can detect redundant retransmission
			 * in S|R and plain R frames and clear it.
			 * undo_retrans is decreased above, L|R frames
			 * are accounted above as well.
			 */
			 //Èç¹ûskb±»D-SACK£¬²¢ÇÒËüµÄÖØ´«±êÖ¾»¹Î´±»Çå³ý£¬ÄÇÃ´ÏÖÔÚÇå³ý¡£ 
			if (dup_sack && (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS))
			{
				TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_RETRANS;
				tp->retrans_out -= tcp_skb_pcount(skb);
				tp->retransmit_skb_hint = NULL;
			}
		}

		/* SACK enhanced FRTO (RFC4138, Appendix B): Clearing correct
		 * due to in-order walk
		 */
		if (after(end_seq, tp->frto_highmark))
			flag &= ~FLAG_ONLY_ORIG_SACKED;
	}

	//Èç¹ûretrans_out²»Îª0£¬ÇÒ´¦ÓÚRecovery×´Ì¬£¬ËµÃ÷ÓÐÖØ´«°ü¶ªÊ§£¬½øÐÐ´¦Àí¡£ 

	//µ±ÓµÈû×´Ì¬»ú´¦ÓÚRecovery×´Ì¬ÖÐ£¬
	if (tp->retrans_out && after(highest_sack_end_seq, tp->lost_retrans_low) && icsk->icsk_ca_state == TCP_CA_Recovery)
		flag |= tcp_mark_lost_retrans(sk, highest_sack_end_seq);

	tcp_verify_left_out(tp);

	 //* ¸üÐÂÂÒÐò¶ÓÁÐ³¤¶È¡£ 
     //* ÂÒÐò¶ÓÁÐµÄ³¤¶È = fackets_out - reord + 1£¬reord¼ÇÂ¼´ÓµÚ¼¸¸ö°ü¿ªÊ¼ÂÒÐò 
	if ((reord < tp->fackets_out) && icsk->icsk_ca_state != TCP_CA_Loss &&
	    (!tp->frto_highmark || after(tp->snd_una, tp->frto_highmark)))
		tcp_update_reordering(sk, tp->fackets_out - reord, 0);

out:

#if FASTRETRANS_DEBUG > 0
	BUG_TRAP((int)tp->sacked_out >= 0);
	BUG_TRAP((int)tp->lost_out >= 0);
	BUG_TRAP((int)tp->retrans_out >= 0);
	BUG_TRAP((int)tcp_packets_in_flight(tp) >= 0);
#endif
	return flag;
}

/* If we receive more dupacks than we expected counting segments
 * in assumption of absent reordering, interpret this as reordering.
 * The only another reason could be bug in receiver TCP.
 */

//The routine tries to calculate the reordering length for Reno implementations
//where we have no idea of out - of - order segments received by the peer. Normally,
//with SACK implementation, we can calculate the reordering length from SACK
//block highest and lowest sequence spaces. With Reno, we have no such case. 
//Reordering can be observed only if we receive more than expected duplicate ACKs.
// This may happen in case the lost segment reaches the receiver out - of - order after we have
//already retransmitted it. In such cases, we get a duplicate ACK for the retransmitted
//segment which will be one more than expected. We can safely assume this as reordering. 
//In such cases where the sum of SACKed - out segments and lost segments is
//more than the segments so far transmitted within the window 
//we need to update reordering length as the number of packets transmitted but not
//yet ACKed within the window (tp¡úpackets_out)by calling tcp_update_reordering()
static void tcp_check_reno_reordering(struct sock *sk, const int addend)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 holes;

	holes = max(tp->lost_out, 1U);
	holes = min(holes, tp->packets_out);

	if ((tp->sacked_out + holes) > tp->packets_out)
	{
		//we adjust the sacked - out segments as the difference between packets transmitted 
		//and lost segments
		tp->sacked_out = tp->packets_out - holes;
		//update the reordering length to a number of packets transmitted in the current window 
		//In Reno, we have no idea which segment caused the generation of duplicate ACK and we 
		//are equating packets sacked and packets lost to exceed the total length of the transmission; 
		//we need to assume that the entire transmission is reordered
		tcp_update_reordering(sk, tp->packets_out + addend, 0);
	}
}

/* Emulate SACKs for SACKless connection: account for a new dupack. */
//Reno implementation does not have any idea of any out - of - order segments that are
//received by the peer. We try to simulate SACK - out segments from the duplicate
//acknowledgments we receive. This makes our work simpler by having a common
//routine for SACK as well as Reno implementations. 
static void tcp_add_reno_sack(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	// increment SACK count emulated for Reno
	tp->sacked_out++;
	//check if the reordering length needs to be modified because of the duplicate ACK received.
	//The idea to check reordering is simple. If the sum of lost and sacked segments is more than 
	//the packets transmitted, it means that some of the segments that were considered lost and 
	//retransmitted were actually not lost but instead reached late. This happened because of 
	//reordering of segments. In this case the original transmissions and the retransmissions both 
	//got received, and duplicate ACK was generated for both.
	tcp_check_reno_reordering(sk, 0);
	tcp_verify_left_out(tp);
}

/* Account for ACK, ACKing some data in Reno Recovery phase. */
//Recalculates SACKed-out segments based on the ACK we received. 
//Since Reno implementation can't see what all the segments have reached,
//it assumes that each duplicate ACK means that a segment has reached the 
//receiver after the hole.
static void tcp_remove_reno_sacks(struct sock *sk, int acked)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (acked > 0) 
	{
		/* One ACK acked hole. The rest eat duplicate ACKs. */
		/*
	 		ÊÕµ½Õý³£ACK£¬²»ÔÚRecovery×´Ì¬¡£ 
         * ÊÕµ½Cummulative ACK£¬È·ÈÏÍêËùÓÐµÄsacked°ü¡£ 
		*/
		//If SACK count is n, it means that n segments after one hole has
		//reached the receiver when the reality may be very different. If we have
		//ACKed n + 1 segments, where n is the number of sacked - out segments (duplicate
		//ACKs), Reno SACK counter is reset because all the sacked out segments are
		//covered by the ACK. Otherwise if segments covered by ACK is less than SACKed-out 
		//segments, we decrement the SACKed - out segments by ACKed segments -1 (1 for hole) at line
		if (acked-1 >= tp->sacked_out)
			tp->sacked_out = 0;
		else  //ÊÕµ½Partial ACK£¬È·ÈÏÁË²¿·Ösack°ü
			tp->sacked_out -= acked-1;
	}
	//¼ì²éÊÇ·ñÓÐÂÒÐò£¬ÓÐµÄ»°¸üÐÂtp->reordering
	tcp_check_reno_reordering(sk, acked);
	tcp_verify_left_out(tp);
}

static inline void tcp_reset_reno_sack(struct tcp_sock *tp)
{
	tp->sacked_out = 0;
}

/* F-RTO can only be used if TCP has never retransmitted anything other than
 * head (SACK enhanced variant from Appendix B of RFC4138 is more robust here)
 */
int tcp_use_frto(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	if (!sysctl_tcp_frto)
		return 0;

	if (IsSackFrto())
		return 1;

	/* Avoid expensive walking of rexmit queue if possible */
	if (tp->retrans_out > 1)
		return 0;

	skb = tcp_write_queue_head(sk);
	skb = tcp_write_queue_next(sk, skb);	/* Skips head */
	tcp_for_write_queue_from(skb, sk)
	{
		if (skb == tcp_send_head(sk))
			break;
		if (TCP_SKB_CB(skb)->sacked&TCPCB_RETRANS)
			return 0;
		/* Short-circuit when first non-SACKed skb has been checked */
		if (!(TCP_SKB_CB(skb)->sacked&TCPCB_SACKED_ACKED))
			break;
	}
	return 1;
}

/* RTO occurred, but do not yet enter Loss state. Instead, defer RTO
 * recovery a bit and use heuristics in tcp_process_frto() to detect if
 * the RTO was spurious. Only clear SACKED_RETRANS of the head here to
 * keep retrans_out counting accurate (with SACK F-RTO, other than head
 * may still have that bit set); TCPCB_LOST and remaining SACKED_RETRANS
 * bits are handled if the Loss state is really to be entered (in
 * tcp_enter_frto_loss).
 *
 * Do like tcp_enter_loss() would; when RTO expires the second time it
 * does:
 *  "Reduce ssthresh if it has not yet been made inside this window."
 */
void tcp_enter_frto(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	if ((!tp->frto_counter && icsk->icsk_ca_state <= TCP_CA_Disorder) ||
	    tp->snd_una == tp->high_seq ||
	    ((icsk->icsk_ca_state == TCP_CA_Loss || tp->frto_counter) &&
	     !icsk->icsk_retransmits)) {
		tp->prior_ssthresh = tcp_current_ssthresh(sk);
		/* Our state is too optimistic in ssthresh() call because cwnd
		 * is not reduced until tcp_enter_frto_loss() when previous F-RTO
		 * recovery has not yet completed. Pattern would be this: RTO,
		 * Cumulative ACK, RTO (2xRTO for the same segment does not end
		 * up here twice).
		 * RFC4138 should be more specific on what to do, even though
		 * RTO is quite unlikely to occur after the first Cumulative ACK
		 * due to back-off and complexity of triggering events ...
		 */
		if (tp->frto_counter)
		{
			u32 stored_cwnd;
			stored_cwnd = tp->snd_cwnd;
			tp->snd_cwnd = 2;
			tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
			tp->snd_cwnd = stored_cwnd;
		}
		else 
		{
			tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
		}
		/* ... in theory, cong.control module could do "any tricks" in
		 * ssthresh(), which means that ca_state, lost bits and lost_out
		 * counter would have to be faked before the call occurs. We
		 * consider that too expensive, unlikely and hacky, so modules
		 * using these in ssthresh() must deal these incompatibility
		 * issues if they receives CA_EVENT_FRTO and frto_counter != 0
		 */
		tcp_ca_event(sk, CA_EVENT_FRTO);
	}

	tp->undo_marker = tp->snd_una;
	tp->undo_retrans = 0;

	skb = tcp_write_queue_head(sk);
	if (TCP_SKB_CB(skb)->sacked & TCPCB_RETRANS)
		tp->undo_marker = 0;
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS) {
		TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_RETRANS;
		tp->retrans_out -= tcp_skb_pcount(skb);
	}
	tcp_verify_left_out(tp);

	/* Too bad if TCP was application limited */
	tp->snd_cwnd = min(tp->snd_cwnd, tcp_packets_in_flight(tp) + 1);

	/* Earlier loss recovery underway (see RFC4138; Appendix B).
	 * The last condition is necessary at least in tp->frto_counter case.
	 */
	if (IsSackFrto() && (tp->frto_counter ||
	    ((1 << icsk->icsk_ca_state) & (TCPF_CA_Recovery|TCPF_CA_Loss))) &&
	    after(tp->high_seq, tp->snd_una)) {
		tp->frto_highmark = tp->high_seq;
	} else {
		tp->frto_highmark = tp->snd_nxt;
	}
	tcp_set_ca_state(sk, TCP_CA_Disorder);
	tp->high_seq = tp->snd_nxt;
	tp->frto_counter = 1;
}

/* Enter Loss state after F-RTO was applied. Dupack arrived after RTO,
 * which indicates that we should follow the traditional RTO recovery,
 * i.e. mark everything lost and do go-back-N retransmission.
 */
static void tcp_enter_frto_loss(struct sock *sk, int allowed_segments, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	tp->lost_out = 0;
	tp->retrans_out = 0;
	if (tcp_is_reno(tp))
		tcp_reset_reno_sack(tp);

	tcp_for_write_queue(skb, sk) {
		if (skb == tcp_send_head(sk))
			break;

		TCP_SKB_CB(skb)->sacked &= ~TCPCB_LOST;
		/*
		 * Count the retransmission made on RTO correctly (only when
		 * waiting for the first ACK and did not get it)...
		 */
		if ((tp->frto_counter == 1) && !(flag&FLAG_DATA_ACKED))
		{
			/* For some reason this R-bit might get cleared? */
			if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS)
				tp->retrans_out += tcp_skb_pcount(skb);
			/* ...enter this if branch just for the first segment */
			flag |= FLAG_DATA_ACKED;
		} else {
			if (TCP_SKB_CB(skb)->sacked & TCPCB_RETRANS)
				tp->undo_marker = 0;
			TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_RETRANS;
		}

		/* Don't lost mark skbs that were fwd transmitted after RTO */
		if (!(TCP_SKB_CB(skb)->sacked&TCPCB_SACKED_ACKED) &&
		    !after(TCP_SKB_CB(skb)->end_seq, tp->frto_highmark)) {
			TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
			tp->lost_out += tcp_skb_pcount(skb);
		}
	}
	tcp_verify_left_out(tp);

	tp->snd_cwnd = tcp_packets_in_flight(tp) + allowed_segments;
	tp->snd_cwnd_cnt = 0;
	tp->snd_cwnd_stamp = tcp_time_stamp;
	tp->frto_counter = 0;
	tp->bytes_acked = 0;

	tp->reordering = min_t(unsigned int, tp->reordering, sysctl_tcp_reordering);
	tcp_set_ca_state(sk, TCP_CA_Loss);
	tp->high_seq = tp->frto_highmark;
	TCP_ECN_queue_cwr(tp);

	tcp_clear_retrans_hints_partial(tp);
}

static void tcp_clear_retrans_partial(struct tcp_sock *tp)
{
	tp->retrans_out = 0;
	tp->lost_out = 0;
	tp->undo_marker = 0;
	tp->undo_retrans = 0;
}

void tcp_clear_retrans(struct tcp_sock *tp)
{
	tcp_clear_retrans_partial(tp);

	tp->fackets_out = 0;
	tp->sacked_out = 0;
}

/* Enter Loss state. If "how" is not zero, forget all SACK information
 * and reset tags completely, otherwise preserve SACKs. If receiver
 * dropped its ofo queue, we will know this due to reneging detection.
 */

//Tag the lost segment from the current window and also
//reduce the rate of transmission of data by performing slow - start 

//½øÈëLoss×´Ì¬£¬ÊÇ·ñÇå³ýSACK±êÖ¾È¡¾öÓÚhow£¬how²»Îª0ÔòÇå³ý 
//how -- 1 means that we want to mark all the segments in the retransmit queue as lost and at the same
//time we don't initialize tp->undo_marker. tp->undo_marker remains uninitialized, which means that we 
//don't want to undo from the loss state because we know that something is messed up at the receiver and
//so far it is not able to handle unacknowledged segments properly and we need to retransmit all of them 
//once again. We start the slow-start algorithm here. Transmit the first segment in the retransmit queue 
//at line 1037 and reset the retransmit timer
void tcp_enter_loss(struct sock *sk, int how)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	/* Reduce ssthresh if it has not yet been made inside this window. */
	//We do reduce slow-start threshold only if it is not done in the current window.
	//which means that within a window if multiple losses take place, we won ¡¯ t
	//reduce the slow - start threshold every time.

	//If the current congestion window caused packet loss, we need to go back to 
	//the previous congestion window that provided an acceptable rate of
	//data transmission. So, we divide the current congestion into two halves: The first
	//half is for slow - start because it was in the previous congestion window, and the
	//second half is for slow transmission of data (where congestion window is incremented every RTT). 
	//This will get us better congestion control in the second half
	//session that got us into trouble. That is the reason we don ¡¯ t decrease slow - start
	//threshold value twice for the same window. We just start with one congestion
	//window every time we sense a loss through retransmission timer firing. 

	//icsk->icsk_ca_state <= TCP_CA_Disorder
	//If we are entering into the loss state from the open | disorder state, we have not yet reduced
	//the slow-start threshold for the window of data.

	//tp->snd_una == tp->high_seq 
	//it means that in whatever state we are (other than open | disorder state), all the data from the 
	//window that got us into the state, prior to retransmission timer expiry, has been acknowledged.
	//this is a new window 

	//(icsk->icsk_ca_state == TCP_CA_Loss && !icsk->icsk_retransmits)
	//If we are already in the loss state
	//and have not yet retransmitted anything. The condition may arise in case we
	//are not able to retransmit anything because of local congestion.
	if (icsk->icsk_ca_state <= TCP_CA_Disorder || tp->snd_una == tp->high_seq ||
	    (icsk->icsk_ca_state == TCP_CA_Loss && !icsk->icsk_retransmits)) 
	{
		tp->prior_ssthresh = tcp_current_ssthresh(sk);
		///¼õÐ¡snd_ssthresh 
		tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
		tcp_ca_event(sk, CA_EVENT_LOSS);
	}
	tp->snd_cwnd	   = 1;
	tp->snd_cwnd_cnt   = 0;
	tp->snd_cwnd_stamp = tcp_time_stamp;

	tp->bytes_acked = 0;
	//We clear all the counters related to retransmissions, because we
	//are going to do fresh calculations in the next step.
	tcp_clear_retrans_partial(tp);

	if (tcp_is_reno(tp))
		tcp_reset_reno_sack(tp);

	if (!how)
	{
		/* Push undo marker, if it was plain RTO and nothing was retransmitted. */
		// we are eligible for undoing from the loss state.
		tp->undo_marker = tp->snd_una;
		tcp_clear_retrans_hints_partial(tp);
	} 
	else 
	{
		tp->sacked_out = 0;
		tp->fackets_out = 0;
		tcp_clear_all_retrans_hints(tp);
	}

	tcp_for_write_queue(skb, sk)
	{
		if (skb == tcp_send_head(sk))
			break;

		//why???
		if (TCP_SKB_CB(skb)->sacked & TCPCB_RETRANS)
			tp->undo_marker = 0;
	
		//Çå³ýTCPCB_LOSTºÍTCPCB_SACKED_RETRANS±êÖ¾Î»				
		TCP_SKB_CB(skb)->sacked &= (~TCPCB_TAGBITS)|TCPCB_SACKED_ACKED;
		
		//Èç¹ûhowÎª1,ÔòËµÃ÷²»¹Üsack¶Î£¬´ËÊ±±ê¼ÇËùÓÐµÄ¶ÎÎª¶ªÊ§
		if (!(TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED) || how)
		{
			TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_ACKED;
			TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
			tp->lost_out += tcp_skb_pcount(skb);
		}
	}
	tcp_verify_left_out(tp);

	tp->reordering = min_t(unsigned int, tp->reordering, sysctl_tcp_reordering);
	tcp_set_ca_state(sk, TCP_CA_Loss);
	tp->high_seq = tp->snd_nxt;
	//why???
	//The next new data segment that the sender
	//sends will have a CWR bit set in the TCP header informing the receiver that it has
	//reduced its congestion window.
	TCP_ECN_queue_cwr(tp);
	/* Abort F-RTO algorithm if one is in progress */
	tp->frto_counter = 0;
}

//This routine checks if we need to destroy all the SACK block received from the peer because it may be buggy. 
//If so, we need to enter into the loss state because all the SACKed segments are marked lost. The indication 
//is that the first segment in  the write queue is marked as SACKed. This should never be the case because if 
//the first unACKed segment in the write queue has reached the receiver, then it should be ACKed as in-sequence 
//data.If this segment is SACKed,it means that this in - order segment is still lying in the out-of-order queue 
//even though there is no hole in the data received prior to this segment. In this case, we mark all the segments
//in the retransmit queue as lost by calling tcp_enter_loss()
static int tcp_check_sack_reneging(struct sock *sk)
{
	struct sk_buff *skb;

	/* If ACK arrived pointing to a remembered SACK,
	 * it means that our remembered SACKs do not reflect
	 * real state of receiver i.e.
	 * receiver _host_ is heavily congested (or buggy).
	 * Do processing similar to RTO timeout.
	 */
	if ((skb = tcp_write_queue_head(sk)) != NULL && (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED))
	{		
		struct inet_connection_sock *icsk = inet_csk(sk);
		NET_INC_STATS_BH(LINUX_MIB_TCPSACKRENEGING);
		//we set the second argument of tcp_enter_loss to 1. 
		//Because the reason for entering into loss state is entirely different here.
		//The reason is that whatever out-of-order segments have reached the receiver are discarded by the receiver and we
		//need to retransmit all the data within the window once again. So, it is not the congestion state 
		//but the receiver ¡¯ s mismanagement that causes us to enter into the loss
		//state. So, we cannot undo from the loss state.
		tcp_enter_loss(sk, 1);
		icsk->icsk_retransmits++;
		//Transmit the first segment in the retransmit queue
		tcp_retransmit_skb(sk, tcp_write_queue_head(sk));
		//reset the retransmit timer 
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS, icsk->icsk_rto, TCP_RTO_MAX);
		return 1;
	}
	return 0;
}

//In the case of SACK implementation, we exactly know FACKed-out segments, but in Reno implementation 
//we hardly have an idea of it. So, we consider only SACKed-out segments (number of duplicate ACKs + 1) 
//as FACKed-out segments in Reno implementation. We add one because we consider one segment lost at the 
//head of the retransmit queue in the case of Reno Implementation. 
static inline int tcp_fackets_out(struct tcp_sock *tp)
{
	return tcp_is_reno(tp) ? tp->sacked_out+1 : tp->fackets_out;
}

static inline int tcp_skb_timedout(struct sock *sk, struct sk_buff *skb)
{
	return (tcp_time_stamp - TCP_SKB_CB(skb)->when > inet_csk(sk)->icsk_rto);
}

//We try to find out if the head of the retransmit queue is not ACKed even after it
//has elapsed more than RTO since it was transmitted. Timestamp is stored in each
//segment (skb->when) when it is transmitted in tcp_transmit_skb().The retransmit 
//timer won't fire for the next segment (head of the retransmit queue) even if the 
//segment has elapsed more than RTO (tp->rto) because the retransmit timer is 
//started only after the ACK for the previous segment was received. When we receive
//ACK for a segment, we set a retransmission timeout timer for the next segment in
//tcp_clean_rtx_queue()->tcp_rearm_rto().The timeout value for the retransmission timer
//is set to tp->rto, even though the next segment was transmitted much earlier. So,
//timeout for the next segment is slightly overestimated by time lapsed since it was
//transmitted and the ACK for the previous segment arrived.  We can detect early
//timeout for the retransmit queue head by calling tcp_head_timedout()
static inline int tcp_head_timedout(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	//we check if there are any segments which are transmitted (tp¡úpackets_out > 0). If
	//so, we check if the head of the list has timed out by using the buffer's timestamp
	//stored at the time when it is transmitted (TCP_SKB_CB(skb->when))
	return tp->packets_out && tcp_skb_timedout(sk, tcp_write_queue_head(sk));
}

/* Linux NewReno/SACK/FACK/ECN state machine.
 * --------------------------------------
 *
 * "Open"	Normal state, no dubious events, fast path.
 * "Disorder"   In all the respects it is "Open",
 *		but requires a bit more attention. It is entered when
 *		we see some SACKs or dupacks. It is split of "Open"
 *		mainly to move some processing from fast path to slow one.
 * "CWR"	CWND was reduced due to some Congestion Notification event.
 *		It can be ECN, ICMP source quench, local device congestion.
 * "Recovery"	CWND was reduced, we are fast-retransmitting.
 * "Loss"	CWND was reduced due to RTO timeout or SACK reneging.
 *
 * tcp_fastretrans_alert() is entered:
 * - each incoming ACK, if state is not "Open"
 * - when arrived ACK is unusual, namely:
 *	* SACK
 *	* Duplicate ACK.
 *	* ECN ECE.
 *
 * Counting packets in flight is pretty simple.
 *
 *	in_flight = packets_out + retrans_out - left_out 
 *
 *	packets_out is SND.NXT-SND.UNA counted in packets.
 *
 *	retrans_out is number of retransmitted segments.
 *
 *	left_out is number of segments left network, but not ACKed yet.
 *
 *		left_out = sacked_out + lost_out  
 *
 *     sacked_out: Packets, which arrived to receiver out of order
 *		   and hence not ACKed. With SACKs this number is simply
 *		   amount of SACKed data. Even without SACKs
 *		   it is easy to give pretty reliable estimate of this number,
 *		   counting duplicate ACKs.
 *
 *       lost_out: Packets lost by network. TCP has no explicit
 *		   "loss notification" feedback from network (for now).
 *		   It means that this number can be only _guessed_.
 *		   Actually, it is the heuristics to predict lossage that
 *		   distinguishes different algorithms.
 *
 *	F.e. after RTO, when all the queue is considered as lost,
 *	lost_out = packets_out and in_flight = retrans_out.
 *
 *		Essentially, we have now two algorithms counting
 *		lost packets.
 *
 *		FACK: It is the simplest heuristics. As soon as we decided
 *		that something is lost, we decide that _all_ not SACKed
 *		packets until the most forward SACK are lost. I.e.
 *		lost_out = fackets_out - sacked_out and left_out = fackets_out.
 *		It is absolutely correct estimate, if network does not reorder
 *		packets. And it loses any connection to reality when reordering
 *		takes place. We use FACK by default until reordering
 *		is suspected on the path to this destination.
 *
 *		NewReno: when Recovery is entered, we assume that one segment
 *		is lost (classic Reno). While we are in Recovery and
 *		a partial ACK arrives, we assume that one more packet
 *		is lost (NewReno). This heuristics are the same in NewReno
 *		and SACK.
 *
 *  Imagine, that's all! Forget about all this shamanism about CWND inflation
 *  deflation etc. CWND is real congestion window, never inflated, changes
 *  only according to classic VJ rules.
 *
 * Really tricky (and requiring careful tuning) part of algorithm
 * is hidden in functions tcp_time_to_recover() and tcp_xmit_retransmit_queue().
 * The first determines the moment _when_ we should reduce CWND and,
 * hence, slow down forward transmission. In fact, it determines the moment
 * when we decide that hole is caused by loss, rather than by a reorder.
 *
 * tcp_xmit_retransmit_queue() decides, _what_ we should retransmit to fill
 * holes, caused by lost packets.
 *
 * And the most logically complicated part of algorithm is undo
 * heuristics. We detect false retransmits due to both too early
 * fast retransmit (reordering) and underestimated RTO, analyzing
 * timestamps and D-SACKs. When we detect that some segments were
 * retransmitted by mistake and CWND reduction was wrong, we undo
 * window reduction and abort recovery phase. This logic is hidden
 * inside several functions named tcp_try_undo_<something>.
 */

/* This function decides, when we should leave Disordered state
 * and enter Recovery phase, reducing congestion window.
 *
 * Main question: may we further continue forward transmission
 * with the same cwnd?
 */
//Õâ¸öº¯ÊýÖ÷ÒªÊÇÓÃÀ´ÅÐ¶ÏÊÇ·ñÐèÒª½øÈërecover×´Ì¬
static int tcp_time_to_recover(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 packets_out;

	/* Do not perform any recovery during F-RTO algorithm */
	if (tp->frto_counter)
		return 0;

	/* Trick#1: The loss is proven. */
	if (tp->lost_out)
		return 1;

	/* Not-A-Trick#2 : Classic rule... */
	//Check here is the number of Facked-out segments that have exceeded reordering length
	//If the condition is true, it means that some of the segments at the beginning of the 
	//retransmit queue are considered lost because the rest of them covered by reorder length 
	//are considered as being reordered in the network and will appear sooner or later. 
	if (tcp_fackets_out(tp) > tp->reordering)
		return 1;

	/* Trick#3 : when we use RFC2988 timer restart, fast
	 * retransmit can be triggered by timeout of queue head.
	 */
	//we check if the head of the retransmit queue has timed out 
	//The retransmission timer is reset on reception of each ACK. The packet should be ACKed 
	//within an estimated RTO. If the time for the packet exceeds RTO, it is another way to 
	//signal early retransmission.
	if (tcp_head_timedout(sk))
		return 1;

	/* Trick#4: It is still not OK... But will it be useful to delay
	 * recovery more?
	 */
	packets_out = tp->packets_out;
	if (packets_out <= tp->reordering &&
	    tp->sacked_out >= max_t(__u32, packets_out/2, sysctl_tcp_reordering) &&
	    !tcp_may_send_now(sk)) 
	{
		/* We have nothing to send. This connection is limited
		 * either by receiver window or by application.
		 */
		return 1;
	}

	return 0;
}

/* RFC: This is from the original, I doubt that this is necessary at all:
 * clear xmit_retrans hint if seq of this skb is beyond hint. How could we
 * retransmitted past LOST markings in the first place? I'm not fully sure
 * about undo and end of connection cases, which can cause R without L?
 */
static void tcp_verify_retransmit_hint(struct tcp_sock *tp, struct sk_buff *skb)
{
	if ((tp->retransmit_skb_hint != NULL) &&
	    before(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(tp->retransmit_skb_hint)->seq))
		tp->retransmit_skb_hint = NULL;
}

/* Mark head of queue up as lost. */
//This routine is called to mark a specified number of segments lost starting from the head of the retransmit queue.
//packets -- the number of segments to be marked lost
static void tcp_mark_head_lost(struct sock *sk, int packets)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int cnt;

	BUG_TRAP(packets <= tp->packets_out);
	if (tp->lost_skb_hint) 
	{
		skb = tp->lost_skb_hint;
		cnt = tp->lost_cnt_hint;
	} 
	else
	{
		skb = tcp_write_queue_head(sk);
		cnt = 0;
	}

	tcp_for_write_queue_from(skb, sk)
	{
		if (skb == tcp_send_head(sk))
			break;
		/* TODO: do this better */
		/* this is not the most efficient way to do this... */
		tp->lost_skb_hint = skb;
		tp->lost_cnt_hint = cnt;
		cnt += tcp_skb_pcount(skb);
		if (cnt > packets || after(TCP_SKB_CB(skb)->end_seq, tp->high_seq))
			break;

		//The segments are marked lost only if they are neither
		//SACKed/retransmitted or not already marked lost
		if (!(TCP_SKB_CB(skb)->sacked & (TCPCB_SACKED_ACKED|TCPCB_LOST))) 
		{
			TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
			tp->lost_out += tcp_skb_pcount(skb);
			tcp_verify_retransmit_hint(tp, skb);
		}
	}
	tcp_verify_left_out(tp);
}

/* Account newly detected lost packet(s) */

static void tcp_update_scoreboard(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	//In the case where FACK is implemented, we take difference of FACKed-out segment
	//and disorder length to estimate the lost segments. Otherwise we assume that only
	//the head of the retransmit queue is lost. 
	if (tcp_is_fack(tp)) 
	{
		int lost = tp->fackets_out - tp->reordering;
		if (lost <= 0)
			lost = 1;
		tcp_mark_head_lost(sk, lost);
	} 
	else 
	{
		//In the case where SACK is not supported or it is Reno implementation, we have
		//little or no idea of reordering and the segments that have reached the receiver. So,
		//in this case we mark only one segment at the head of the retransmit queue as
		//lost.
		tcp_mark_head_lost(sk, 1);
	}

	/* New heuristics: it is possible only after we switched
	 * to restart timer each time when something is ACKed.
	 * Hence, we can detect timed out packets during fast
	 * retransmit without falling to slow start.
	 */
	//In the case where head of the retransmit queue has timed out, we check for
	//each segment in the retransmit queue which has timed out in loop 
	if (!tcp_is_reno(tp) && tcp_head_timedout(sk))
	{
		struct sk_buff *skb;

		skb = tp->scoreboard_skb_hint ? tp->scoreboard_skb_hint : tcp_write_queue_head(sk);

		tcp_for_write_queue_from(skb, sk)
		{
			if (skb == tcp_send_head(sk))
				break;
			if (!tcp_skb_timedout(sk, skb))
				break;

			if (!(TCP_SKB_CB(skb)->sacked & (TCPCB_SACKED_ACKED|TCPCB_LOST))) 
			{
				//we mark the segment as lost and increment the lost counter. This is 
				//just a proactive approach or a protective way to sense any congestion 
				//and retransmit at least one segment so that the retransmit timer does 
				//not experience timeout and we can avoid the loss state.
				TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
				tp->lost_out += tcp_skb_pcount(skb);
				tcp_verify_retransmit_hint(tp, skb);
			}
		}

		tp->scoreboard_skb_hint = skb;

		tcp_verify_left_out(tp);
	}
}

/* CWND moderation, preventing bursts due to too big ACKs
 * in dubious situations.
 */
static inline void tcp_moderate_cwnd(struct tcp_sock *tp)
{
	tp->snd_cwnd = min(tp->snd_cwnd, tcp_packets_in_flight(tp)+tcp_max_burst(tp));
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* Lower bound on congestion window is slow start threshold
 * unless congestion avoidance choice decides to overide it.
 */
static inline u32 tcp_cwnd_min(const struct sock *sk)
{
	const struct tcp_congestion_ops *ca_ops = inet_csk(sk)->icsk_ca_ops;

	return ca_ops->min_cwnd ? ca_ops->min_cwnd(sk) : tcp_sk(sk)->snd_ssthresh;
}

/* Decrease cwnd each second ack. */
//try to reduce the congestion window on the reception of every second ACK
static void tcp_cwnd_down(struct sock *sk, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int decr = tp->snd_cwnd_cnt + 1;

	if ((flag&(FLAG_ANY_PROGRESS|FLAG_DSACKING_ACK)) || (tcp_is_reno(tp) && !(flag&FLAG_NOT_DUP)))
	{
		tp->snd_cwnd_cnt = decr&1;
		decr >>= 1;

		if (decr && tp->snd_cwnd > tcp_cwnd_min(sk))
			tp->snd_cwnd -= decr;
		//try to keep the congestion window such that at the most one new segment
		//can be transmitted which is calculated as packets_in_flight() + 1. 
		//Otherwise if the congestion window is less than the number of packets in 
		//flight + 1, we wait for more segments to be ACKed before we can transmit 
		//any new segment.
		tp->snd_cwnd = min(tp->snd_cwnd, tcp_packets_in_flight(tp)+1);
		tp->snd_cwnd_stamp = tcp_time_stamp;
	}
}

/* Nothing was retransmitted or returned timestamp is less
 * than timestamp of the first retransmission.
 */
//From this logic we can conclude that we can undo from loss state as soon as we get
//a duplicate ACK from the window that got us into congestion because the timestamp 
//echoed will always be less than the timestamp for the first retransmitted segment.
// We get back to the congestion state prior to entering the congestion state,
//but we exit the loss state only if SACK is supported over the connection; otherwise
//we remain in the loss state even with a high rate of data transmission.

//We undo from the recovery state only if we received an ACK that ACKed full (tp¡úhigh_seq) or
//partial (current tp¡úsnd_una is higher than the value before the ACK being processed arrived)
//data but not from retransmission but from original transmissions (tp->retrans_stamp > tp->rcv_tsecr). 

//For the same reason, tcp_try_undo_recovery() is called only when we get partial/full data ACKed, 
//whereas tcp_try_undo_loss() is called irrespective of the fact that we obtained a duplicate ACK 
//or data ACKed in tcp_fastretrans_alert().
static inline int tcp_packet_delayed(struct tcp_sock *tp)
{
	//If tp¡úrcv_tsecr < tp¡úretrans_stamp, it means that the echoed timestamp was from
	//the original transmission because the retransmission timestamp is higher than the
	//echoed timestamp. If the echoed timestamp was greater than the timestamp of the
	//first retransmission, it means that the retransmission has filled the hole. 
	//To understand which timestamp is echoed in the case of reordering, just check RFC 1323.
	//According to this document, we echo the timestamp from the last segment that
	//advanced the left window in case we receive an out - of - order segment. When a
	//segment arrives that fills a gap, we echo back the timestamp from this segment. The
	//reason for this is that the segment that fills the gap represents the true congestion
	//state of the network
	return !tp->retrans_stamp || (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr &&
		 (__s32)(tp->rx_opt.rcv_tsecr - tp->retrans_stamp) < 0);
}

/* Undo procedures. */

#if FASTRETRANS_DEBUG > 1
static void DBGUNDO(struct sock *sk, const char *msg)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);

	printk(KERN_DEBUG "Undo %s %u.%u.%u.%u/%u c%u l%u ss%u/%u p%u\n",
	       msg,
	       NIPQUAD(inet->daddr), ntohs(inet->dport),
	       tp->snd_cwnd, tcp_left_out(tp),
	       tp->snd_ssthresh, tp->prior_ssthresh,
	       tp->packets_out);
}
#else
#define DBGUNDO(x...) do { } while (0)
#endif

/* ÓÃÀ´³·Ïú¡°ËõÐ¡ÓµÈû´°¿Ú¡±£¬undo±íÊ¾ÐèÒª³·ÏúÂýÆô¶¯ãÐÖµ*/  
//undo -- 0, it means that we can set a congestion window to the value
//prior to entering the congestion state but can ’ t set ssthresh to the value prior to
//entering congestion. This means that we can inject more segments into the network,
//but the rate of increment of the congestion window will be 1 per RTT. 
static void tcp_undo_cwr(struct sock *sk, const int undo)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->prior_ssthresh)
	{
		const struct inet_connection_sock *icsk = inet_csk(sk);

		if (icsk->icsk_ca_ops->undo_cwnd)
			tp->snd_cwnd = icsk->icsk_ca_ops->undo_cwnd(sk);
		else
			//Since half of the congestion window was recorded in the slow - start threshold (tp¡ú
			//snd_ssthresh), we initialize the congestion window to the maximum of current congestion window and double the slow - start threshold value (line 1337) since during
			//the congestion state the congestion window may have increased to a high value if
			//the number of packets in flight is too high at the time of congestion. This will
			//increase the data transmission to a very high value
			tp->snd_cwnd = max(tp->snd_cwnd, tp->snd_ssthresh<<1);  

		if (undo && tp->prior_ssthresh > tp->snd_ssthresh) 
		{
			tp->snd_ssthresh = tp->prior_ssthresh;
			TCP_ECN_withdraw_cwr(tp);
		}
	} 
	else 
	{
		tp->snd_cwnd = max(tp->snd_cwnd, tp->snd_ssthresh);
	}
	//Finally, we try to moderate congestion window in case we have reverted back
	//to the congestion window prior to congestion. This may inflate the congestion to a
	//very high value, suddenly causing a burst of packets in the network difficult to
	//handle. We call tcp_moderate_cwnd(). It may happen that all the ACKs from the
	//last window were lost and on reretransmission after we got ACK for all the data,
	//thereby causing congestion window to grow up to very high value. This may cause
	//a burst of segment to be transmitted. The congestion window is initialized to a
	//minimum of current congestion window and packets in flight + maximum burst
	//. Linux assumes maximum burst to be 3, which means that even with
	//delayed ACK, it can send out a maximum of 3 segments.
	tcp_moderate_cwnd(tp);
	tp->snd_cwnd_stamp = tcp_time_stamp;

	/* There is something screwy going on with the retrans hints after an undo */
	tcp_clear_all_retrans_hints(tp);
}

//Undoing from state means that if we were misled into the congestion state
//because of a packet delayed in the network, reordering of segments, and underestimated RTOs, 
//we can resume the same state as it was before. After entering into
//congestion state, we may retransmit segments marked lost. We can sense undoing
//from the state in case we find that the original transmissions are succeeding. We do
//this by calling tcp_may_undo().


//check if we did false retransmission because of underestimated RTO or packets getting late in the flight 
static inline int tcp_may_undo(struct tcp_sock *tp)
{
	//1. the packet got delayed and reached the receiver before the 
	//retransmitted segment could reach, we will try to slightly improve 
	//the condition by opening a congestion window to increase the flow
	//of data transmission. 
	//2.If the ACK covers all the retransmitted segments, it shouldn't
	//necessarily mean that retransmitted segments filled the hole. 
	//It may also happen that the original packets that reached the receiver 
	//prior to retransmissions got delayed. 

	//if tp->undo_marker is set, we know that we are eligible for undoing from the congestion state. 
	//if tp->undo_retrans is 0, it means that either we have not retransmitted
	//anything or whichever segment was retransmitted has been DSACKed, indicating
	//that the original segments were not lost and they also reached the destination along
	//with the retransmitted segments. It may also happen that the ACKs to the segment
	//transmitted earlier were lost and when we retransmitted them, we got DSACKs for
	//those retransmitted segments. If tp¡úundo_retrans is nonzero, it means that we have
	//retransmitted something. 
	//We check if packets got delayed in the network but reached the destination by calling tcp_packet_delayed().
	return tp->undo_marker && (!tp->undo_retrans || tcp_packet_delayed(tp));
}

/* People celebrate: "We love our President!" */
static int tcp_try_undo_recovery(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	//1.try undo from the state
	if (tcp_may_undo(tp)) 
	{
		//undo from the state
		
		/* Happy end! We did not retransmit anything
		 * or our original transmission succeeded.
		 */
		DBGUNDO(sk, inet_csk(sk)->icsk_ca_state == TCP_CA_Loss ? "loss" : "retrans");
		
		//The routine reverts the congestion variables back to the value that was set prior to entering congestion state
		tcp_undo_cwr(sk, 1);
		if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss)
			NET_INC_STATS_BH(LINUX_MIB_TCPLOSSUNDO);
		else
			NET_INC_STATS_BH(LINUX_MIB_TCPFULLUNDO);
		
		tp->undo_marker = 0;
	}

	//Whether we can
	//leave the congestion state will depend on the TCP implementation and sequence
	//number ACKed. With Reno implementation, we don ¡¯ t want to leave the loss state
	//until something above tp¡úhigh_seq is ACKed to avoid false fastretransmissions
	//This is very well documented in RFC 2582. The idea is that we may have retransmitted 
	//three segments after entering the loss state. When those segments reach the
	//receiver, it will generate a duplicate ACK when those segments are already there
	//in the out - of - order queue. In the case of Reno implementation, we have no idea of
	//SACK/DSACK, so these duplicate ACKs should not be confused with the fast -
	//recovery state we wait for until something above the high sequence is ACKed. New
	//data (above tp¡úhigh_seq) are transmitted only after we have retransmitted all the
	//lost segments and the congestion window allows us to do so. So, new data ACKed
	//means that we have already ACKed new data that are beyond the window that
	//moved us into the congestion state. In this case, we just moderate the congestion
	//window and continue to send out new segments in the loss state until something
	//beyond tp¡úhigh_seq is ACKed. The reason that we are doing this in the loss state
	//is that there may be reordering taking place in the loss state also that may lead to
	//retransmission of segments causing false fast recovery when the retransmitted segments cause duplicate ACKs when tp¡úhigh_seq is ACKed.
	//In the case of SACK implementation, we exit the congestion state (loss) as soon
	//as we ACK tp¡úhigh_seq because the duplicate ACK for the above - explained case
	//will carry DSACK and will differentiate these duplicate ACKs from fast recovery.
	//In the case where we are not able to exit the loss state, we return with TCP_CA_Loss
	//state; otherwise we need to process the open state further.
	
	//2.try to exit the congestion state.

	//2.1.In the case of Reno implementation, we should ACK
	//something beyond tp->high_seq to exit the recovery state. This is done in order to
	//avoid entering a false fast - recovery state in case the retransmissions for segments
	//below tp¡úhigh_seq generate duplicate ACKs.
	//Èç¹û²»Ö§³ÖSACK,ÔòÐèÒª·ÀÖ¹Ðé¼ÙµÄ¿ìËÙÖØ´«£¬ ²»ÄÜÁ¢¼´³·Ïúµ½OPEN×´Ì¬£¬Ö»¶ÔÓµÈû´°¿Ú½øÐÐÎ¢µ÷
	//2.2.In the case of SACK/DSACK implementation, DSACKs are generated for each such duplicate ACKs, so we need not
	//worry and exit the recovery state as soon as tp->high_seq is ACKed. 
	if (tp->snd_una == tp->high_seq && tcp_is_reno(tp)) 
	{
		/* Hold old state until something *above* high_seq
		 * is ACKed. For Reno it is MUST to prevent false
		 * fast retransmits (RFC2582). SACK TCP is safe. */
		// not able to exit the recovery state, so we moderate the congestion
		//window by calling tcp_moderate_cwnd() to slow down the data transmission rate
		//until we get ACK beyond tp¡úhigh_seq.
		tcp_moderate_cwnd(tp);
		return 1;
	}
	
	tcp_set_ca_state(sk, TCP_CA_Open);
	return 0;
}

/* Try to undo cwnd reduction, because D-SACKs acked all retransmitted data */
//check if we received DSACK that clears off tp->undo_retrans field
static void tcp_try_undo_dsack(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	//It may happen that we received acknowledged tp->high_seq and recovered from congestion to the 
	//OPEN state without undoing from the congestion state. So tp->undo_marker and tp->undo_retrans 
	//will still be nonzero. This means that we may still have retransmissions in the network which 
	//may reach the destination later generating DSACK. If we received a duplicate ACK containing 
	//DSACK from the window that got us into the congestion state causing tp->undo_retrans to become
	//zero, we try to undo congestion window reduction. It means that the original transmissions for 
	//all the retransmitted data during the congestion state have reached the receiver generating DSACK.
	//So, our retransmission was false. We won't leave the current state (i.e., TCP_CA_Disorder) but 
	//will reset the congestion state variables values that were set prior to entering the congestion 
	//state. We leave the TCP_CA_Disorder state only when something above tp->high_seq is acked.
	if (tp->undo_marker && !tp->undo_retrans)
	{
		DBGUNDO(sk, "D-SACK");
		//We call tcp_undo_cwr() to get us back to the congestion state prior to entering
		//congestion by adjusting tp->snd_ssthresh and tp->snd_cwnd. This is to increment
		//the rate of data transmission. 
		tcp_undo_cwr(sk, 1);
		//We reset tp->undo_marker, which is a clear indication
		//that we can no longer undo from the congestion state for a current window.
		tp->undo_marker = 0;
		NET_INC_STATS_BH(LINUX_MIB_TCPDSACKUNDO);
	}
}

/* Undo during fast recovery after partial ACK. */
//We return TRUE in case we are not able to undo from partial ACK, 
//and Reno Implementation or Facked out segments are more than current 
//reorder length. Otherwise we return FALSE. 
static int tcp_try_undo_partial(struct sock *sk, int acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	/* Partial ACK arrived. Force Hoe's retransmit. */
	//we want to mark new segments as lost for retransmission by calling 
	//tcp_update_scoreboard() because partial ACK has filled up some of the holes. 
	
	//Reno implementation does not take care of SACK, with SACK implementations, we can predict
	//reordering of Segments in the network and congestion state. This is the reason we
	//return TRUE for every partial ACK for Reno implementations. Reno is highly
	//sensitive to Partial ACKs because SACK implementation Provides much closer
	//estimate of re - ordering.
	int failed = tcp_is_reno(tp) || tp->fackets_out > tp->reordering;

	if (tcp_may_undo(tp)) 
	{
		/* Plain luck! Hole if filled with delayed
		 * packet, rather than with a retransmit.
		 */
		//if all the retransmitted segments got ACKed, we reset a retransmit timestamp
		if (tp->retrans_out == 0)
			tp->retrans_stamp = 0;

		//We update the reordering length because some of the SACKed-out segments are eaten up by the ACK
		tcp_update_reordering(sk, tcp_fackets_out(tp) + acked, 1);

		DBGUNDO(sk, "Hoe");
		tcp_undo_cwr(sk, 0);
		NET_INC_STATS_BH(LINUX_MIB_TCPPARTIALUNDO);

		/* So... Do not make Hoe's retransmit yet.
		 * If the first packet was delayed, the rest
		 * ones are most probably delayed as well.
		 */
		//Since we are able to undo from partial ACK, we can expect more segments to be delayed in the
		//network. That is the reason we don't want to retransmit more segments but can
		//either transmit new segments or do forward retransmissions (reset flag) 
		failed = 0;
	}
	return failed;
}

/* Undo during loss recovery after partial ACK. */
static int tcp_try_undo_loss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//In case we receive ACK for the retransmitted segment, it means that the loss is proven and 
	//we continue retransmitting lost segments. Or we receive partial ACK from the original segment, 
	//and we know that the packet got delayed in the network.
	if (tcp_may_undo(tp)) 
	{
		//we undo from loss state. We clear the TCPCB_LOST bit from each segment in the retransmit queue
		//This means that none of the segment is considered lost, and the loss counter is reset
		//ÒÆ³ý¼Ç·ÖÅÆÖÐËùÓÐ¶ÎµÄLOSS±ê¼Ç£¬´Ó¶øÊ¹·¢ËÍ·½¼ÌÐø·¢ËÍÐÂÊý¾Ý¶ø²»ÔÙÖØ´«
		struct sk_buff *skb;
		tcp_for_write_queue(skb, sk) 
		{
			if (skb == tcp_send_head(sk))
				break;
			TCP_SKB_CB(skb)->sacked &= ~TCPCB_LOST;
		}

		tcp_clear_all_retrans_hints(tp);

		DBGUNDO(sk, "partial loss");
		tp->lost_out = 0;
		tcp_undo_cwr(sk, 1);
		NET_INC_STATS_BH(LINUX_MIB_TCPLOSSUNDO);
		inet_csk(sk)->icsk_retransmits = 0;
		tp->undo_marker = 0;
		//in case of SACK implementation we enter into the open state, which may finally fall 
		//into the recovery phase. because SACK implementations have good control over the 
		//congestion state. We may enter the recovery state depending on the number of segments 
		//SACKed out immediately.
		//With Reno implementation, we continue with the loss state 
		//until tp->high_seq is ACKed
		if (tcp_is_sack(tp))
			tcp_set_ca_state(sk, TCP_CA_Open);
		return 1;
	}
	return 0;
}

static inline void tcp_complete_cwr(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_ssthresh);
	tp->snd_cwnd_stamp = tcp_time_stamp;
	tcp_ca_event(sk, CA_EVENT_COMPLETE_CWR);
}

//This routine checks if we need to enter into the CWR state or the disorder state.
//We are called only in open, C(ongestion)W(indow)R(eduction), and disorder TCP states.
static void tcp_try_to_open(struct sock *sk, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_verify_left_out(tp);

	//If tp->retrans_out is set to zero, tp->retrans_stamp is set to zero.
	//It may happen that we have left the congestion state without undoing from the state. 
	//If we come here just after entering the open state from the congestion state, we will 
	//try to reset tp->retrans_stamp in case tp->retrans_out is set to zero. We
	//enter into the open state from the congestion state only after all the retransmitted
	//segments are ACKed. So, tp->retrans_out should become zero. In such cases, we
	//should try to reset tp->retrans_stamp because it records the timestamp of the first
	//retransmitted segment. If we don ¡¯ t do this here, and the very next instance we need
	//to retransmit the segment, we will still have the older value in tp¡úretrans_stamp
	//and will not set the new value (check tcp_retransmit_skb()). This may provide us wrong 
	//results in case we are detecting false retransmissions in tcp_may_undo(). tp->retrans_stamp 
	//is useful to check false retransmission
	if (tp->retrans_out == 0)
		tp->retrans_stamp = 0;

	//if ECE flag is set, we enter into the CWR state 
	//This is the place where we can enter into the CWR state in case we received an ECE flag set 
	//in the packet being processed currently.
	if (flag & FLAG_ECE)
		tcp_enter_cwr(sk, 1);

	//we are here only in three TCP states: TCP_CA_Open, TCP_CA_CWR, and TCP_CA_Disorder.
	//We may have entered the CWR state in this routine itself because of the ECE flag set.
	if (inet_csk(sk)->icsk_ca_state != TCP_CA_CWR)
	{
		//we are processing either the TCP_CA_Open state or the TCP_CA_Disorder state here.
	
		int state = TCP_CA_Open;

		//we enter the disorder state in two cases in routine tcp_try_to_open():
		//1. From the open state when we receive first the duplicate ACK.
		//2. When we exit the congestion state (loss) and enter the open state on ACKing 
		//tp->high_seq but without undoing from congestion. This means that tp->
		//undo_retrans and tp->undo_marker are set with a TCP open state, which
		//means that we are not reverting back to the congestion state prior to entering
		//the congestion. With SACK implementation, we can still get DSACK for the
		//retransmissions which will indicate if the congestion state was entered
		//incorrectly.
		//In the latter case, we know that retransmissions are still there in the flight and can
		//expect them in the form of DSACK. So, in case we get ACK for tp->high_seq in
		//the disorder state, we call tcp_try_undo_dsack() to check if we received
		//DSACK that clears off tp->undo_retrans field.

		//1.If we have entered tcp_fastretrans_alert() in the open state, it may be because we received 
		//the first duplicate ACK. In such cases, tcp_left_out() will be a nonzero positive number 
		//because it is set to the number of SACKed-out segments. In Reno implementation, SACKed-out 
		//segments are emulated as duplicate ACKs.
		//We may have entered tcp_fastretrans_alert() with the TCP state as a loss and have just left
		//these states (because tp->high_seq is ACKed with this segment). In this case, if we are not 
		//able to undo from the congestion states, tp->undo_retrans and tp->undo_marker will still be 
		//set to the congestion state value.
		//In both of the above cases, we just set the TCP state to disorder 
		
		//2.In the case where we are already in the disorder state and received an ACK, we just call 
		//tcp_moderate_window() to bring down the transmission rate and do nothing.
		if (tcp_left_out(tp) || tp->retrans_out || tp->undo_marker)
			state = TCP_CA_Disorder;

		if (inet_csk(sk)->icsk_ca_state != state) 
		{
			//can only be a disorder state, We set the state to the disorder state
			tcp_set_ca_state(sk, state);
			tp->high_seq = tp->snd_nxt;
		}
		//slow down the rate of data transmission to send a maximum of three new segments
		
		//we actually restrict ourselves to sending out a maximum of three new segments from here. 
		//This way we enter into the disorder state
		tcp_moderate_cwnd(tp);
	} 
	else 
	{
		tcp_cwnd_down(sk, flag);
	}
}

static void tcp_mtup_probe_failed(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	icsk->icsk_mtup.search_high = icsk->icsk_mtup.probe_size - 1;
	icsk->icsk_mtup.probe_size = 0;
}

static void tcp_mtup_probe_success(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	/* FIXME: breaks with very large cwnd */
	tp->prior_ssthresh = tcp_current_ssthresh(sk);
	tp->snd_cwnd = tp->snd_cwnd *
		       tcp_mss_to_mtu(sk, tp->mss_cache) /
		       icsk->icsk_mtup.probe_size;
	tp->snd_cwnd_cnt = 0;
	tp->snd_cwnd_stamp = tcp_time_stamp;
	tp->rcv_ssthresh = tcp_current_ssthresh(sk);

	icsk->icsk_mtup.search_low = icsk->icsk_mtup.probe_size;
	icsk->icsk_mtup.probe_size = 0;
	tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
}


/* Process an event, which can update packets-in-flight not trivially.
 * Main goal of this function is to calculate new estimate for left_out,
 * taking into account both packets sitting in receiver's buffer and
 * packets lost by network.
 *
 * Besides that it does CWND reduction, when packet loss is detected
 * and changes state of machine.
 *
 * It does _not_ decide what to send, it is made in function
 * tcp_xmit_retransmit_queue().
 */
static void
tcp_fastretrans_alert(struct sock *sk, int pkts_acked, int flag)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int is_dupack = !(flag&(FLAG_SND_UNA_ADVANCED|FLAG_NOT_DUP));
	int do_lost = is_dupack || ((flag & FLAG_DATA_SACKED) && (tp->fackets_out > tp->reordering));

	/* Some technical things:
	 * 1. Reno does not count dupacks (sacked_out) automatically. */
	 
	//Reno implementation simulates SACKed segments based on duplicate ACKs. 
	//In the case where SACK is supported, we account for the SACK count once a SACKed-out segment is ACKed
	//in-sequence (tcp_clean_rtx_queue). But in the case of Reno, segments are never marked
	//SACKed out so we take care of the Reno Sack count here.
	if (!tp->packets_out)
		tp->sacked_out = 0;

	//In the case where the SACK count is zero, the FACK count should also necessarily be to zero 
	//because the FACK count is derived only if at least one segment is SACKed out
	if (WARN_ON(!tp->sacked_out && tp->fackets_out))
		tp->fackets_out = 0;

	/* Now state machine starts.
	 * A. ECE, hence prohibit cwnd undoing, the reduction is required. */
	//congestion that is sensed by by one of the intermediate routers (not ACK),  
	//avoid increasing the congestion window to a very high value when undo from 
	//a non-open state, (tcp_undo_cwr())
	if (flag & FLAG_ECE)
		tp->prior_ssthresh = 0;

	/* B. In all the states check for reneging SACKs. */
	if (tp->sacked_out && tcp_check_sack_reneging(sk))
		return;

	/* C. Process data loss notification, provided it is valid. */
	//(flag & FLAG_DATA_LOST)
		//If we are in the congestion state and we receive a SACK block that covers tp->high_seq, 
		//it means that the new segment transmitted after the lost segment was retransmitted got SACKed. 
		//This gives us indication that the new segment reached before the retransmitted segment reached
		//the receiver. In this case, we can assume that the data in the window are lost. We check for 
		//some more conditions here before declaring that the data are lost.
	//before(tp->snd_una, tp->high_seq)
		//in-sequence data acknowledged so far is below tp->high_seq which means the segment covering 
		//tp->high_seq has reached the receiver as an out-of-order segment that has been SACKed 
	//icsk->icsk_ca_state != TCP_CA_Open 
		//We are in any congestion state other than an OPEN state. It mayhappen that TCP has entered 
		//into the congestion state incorrectly because of either reordering or fast RTO. In such cases, 
		//we are able to undo from the congestion state with tp¡úhigh_seq already set.
	//tp->fackets_out > tp->reordering
		//the number of FACKed segments is greater than the reordered segments. This surely means that 
		//some of the segments at the start of the retransmit queue can be considered lost. The segments 
		//that need to be marked lost are all those segments from the beginning of the queue which are not
		//yet SACKed
	if ((flag & FLAG_DATA_LOST) && before(tp->snd_una, tp->high_seq) 
		&& icsk->icsk_ca_state != TCP_CA_Open && tp->fackets_out > tp->reordering)
	{
		tcp_mark_head_lost(sk, tp->fackets_out - tp->reordering);
		NET_INC_STATS_BH(LINUX_MIB_TCPLOSS);
	}

	/* D. Check consistency of the current state. */
	tcp_verify_left_out(tp);

	/* E. Check state exit conditions. State can be terminated when high_seq is ACKed. */

	//In the open state since there are no retransmissions, we need
	//not have the tp¡úretrans_stamp set. So, we reset it here
	//This is important because we may be sensing congestion and may need to retransmit segments.
	//If tp¡úretrans_stamp is set, we won't be able to record retransmission timestamp for
	//our first retransmission (check tcp_retransmit_skb()) and this will mislead us in
	//detecting false retransmissions.
	if (icsk->icsk_ca_state == TCP_CA_Open) 
	{
		BUG_TRAP(tp->retrans_out == 0);
		//Çå³ýÉÏ´ÎÖØ´«½×¶ÎµÚÒ»¸öÖØ´«¶ÎµÄ·¢ËÍÊ±¼ä
		tp->retrans_stamp = 0;
	} 
	else if (!before(tp->snd_una, tp->high_seq))
	{
		switch (icsk->icsk_ca_state) 
		{
		case TCP_CA_Loss:
			icsk->icsk_retransmits = 0;
			
			if (tcp_try_undo_recovery(sk))
				return;
			break;

		case TCP_CA_CWR:
			/* CWR is to be held something *above* high_seq
			 * is ACKed for CWR bit to reach receiver. */
			 //We don't leave this state until something higher than tp->high_seq (recorded at the time of entering TCP CWR state) is ACKed.
			 //We need to wait for anything above tp->high_seq to be ACKed in order to make sure that the CWR bit has reached the receiver. 
			 //The CWR bit is sent in the very next new segment after we have received an ECE bit from the receiver. 
			if (tp->snd_una != tp->high_seq)
			{
				tcp_complete_cwr(sk);
				tcp_set_ca_state(sk, TCP_CA_Open);
			}
			break;

		case TCP_CA_Disorder:
			tcp_try_undo_dsack(sk);
			//If we have entered the disorder state from the open state without tp->undo_marker
			//set (reception of the first duplicate ACK) or call to tcp_try_undo_dsack() might
			//have cleared tp->undo_marker. In the case where tp->undo_marker is set, we can
			//still enter the open state in case this is Reno implementation because we have
			//nothing like DSACK to catch. Still we can undo from the disorder state in the case
			//where SACK is implemented and we have ACKed something above tp->high_seq
			//because this makes sure that all the data from the window at the time of entering
			//the congestion state have reached the receiver properly. 

			//1. Is tp¡úundo_marker reset?
			//2. Is it Reno implementation (SACK is disabled)?
			//3. If condition 2 is false, have we received ACK for data above tp¡úhigh_seq.
			if (!tp->undo_marker ||
			    /* For SACK case do not Open to allow to undo
			     * catching for all duplicate ACKs. */
			    tcp_is_reno(tp) || tp->snd_una != tp->high_seq)
			{
				tp->undo_marker = 0;
				tcp_set_ca_state(sk, TCP_CA_Open);
			}
			break;

		case TCP_CA_Recovery:
			//This is done because we have ACKed all the
			//data within the window transmitted at the time when we entered the recovery state.
			//Reno emulates duplicate ACKs as SACKed-out segments. Duplicate ACKs were a
			//result of data loss or reordering of segments within the window marked by tp¡ú
			//high_seq. Once we ACK tp¡úhigh_seq, should reset the SACK counter because
			//SACK implementation will automatically have the SACK count set to 0 as all the
			//holes in the window are filled when we ACK tp¡úhigh_seq. In Reno implementation,
			//we need to reset the SACK counter here because there is no way we can detect the
			//filling of holes.
			if (tcp_is_reno(tp))
				tcp_reset_reno_sack(tp);
			if (tcp_try_undo_recovery(sk))
				return;
			tcp_complete_cwr(sk);
			break;
		}
	}

	/* F. Process state. */
	switch (icsk->icsk_ca_state)
	{
	case TCP_CA_Recovery:
		if (!(flag & FLAG_SND_UNA_ADVANCED)) 
		{
			if (tcp_is_reno(tp) && is_dupack)
				tcp_add_reno_sack(sk);
		}
		else  
		{	
			//we received ACK paritially for new data.
			//We check if we can undo from received partial ACK
			//The return value will decide if we want to mark more 
			//segments as lost and carry on with retransmits later 
			do_lost = tcp_try_undo_partial(sk, pkts_acked);
		}
			
		break;
	case TCP_CA_Loss:
		if (flag & FLAG_DATA_ACKED)
			icsk->icsk_retransmits = 0;
		//check partial ACKing in the loss state
		if (!tcp_try_undo_loss(sk)) 
		{
			tcp_moderate_cwnd(tp);
			tcp_xmit_retransmit_queue(sk);
			return;
		}
		//If we are able to undo, we return only if TCP state has not opened.
		//If the TCP state has opened, because of partial ACK. We may look for 
		//the possibility of entering into the recovery state andwe proceed with 
		//default processing of the TCP state
		if (icsk->icsk_ca_state != TCP_CA_Open)
			return;
		/* Loss is undone; fall through to processing in Open state. */
	default:
		//We come here in case TCP has entered any of the congestion state and we received got an ACK for data
		//that are below tp->high_seq (recorded at the time when we entered congestion state) under different 
		//conditions for each TCP state. 
		//We also enter here in case we are in the OPEN state and we received a first duplicate ACK. 

		//In case it is Reno implementation
		if (tcp_is_reno(tp)) 
		{
			//Linux TCP implementation simulates SACK for SACKless Reno implementation in the following way:
			//In case we have ACKed new data, we need to reset Reno SACK counters. 
			if (flag & FLAG_SND_UNA_ADVANCED)
				tcp_reset_reno_sack(tp);
			//In case we have received a duplicate ACK, we need to update the Reno SACK 
			//Since Reno implementation has no idea which segment has reached the receiver out-of-order, it just 
			//increments the SACK counter on reception of every consecutive duplicate ACK. Similarly, it resets 
			//the SACK counter when new data are ACKed by calling tcp_reset_reno_sack().This way Linux TCP 
			//implementation simulates SACK for SACKless Reno implementation
			if (is_dupack)
				tcp_add_reno_sack(sk);
		}

		//This routine check if the DSACK is received that may open the TCP
		//state. If so, we are able to undo from the congestion state prior to entering the
		//recovery state. On reception of each DSACK within the window, tp->undo_retrans
		//is decremented by 1 (see tcp_sacktag_write_queue())
		if (icsk->icsk_ca_state == TCP_CA_Disorder)
			tcp_try_undo_dsack(sk);

		//Check if we need to enter the fast-retransmission fast-recovery state (TCP_CA_Recovery). 
		//We are here only if we have entered tcp_fastretrans_alert() in any of the four states:
		//1. TCP_CA_Open 2. TCP_CA_Disorder 3. TCP_CA_CWR  (4.TCP_CA_Loss)
		if (!tcp_time_to_recover(sk)) 
		{
			//we can't enter into the recovery state. So, we check the possibility of entering the 
			//disorder or CWR state by calling tcp_try_to_open()
			tcp_try_to_open(sk, flag);
			return;
		}

		//we are entering into a fast-retransmit fast-recovery state (TCP_CA_Recovery). 

		/* MTU probe failure: don't reduce cwnd */
		if (icsk->icsk_ca_state < TCP_CA_CWR && icsk->icsk_mtup.probe_size &&
		    tp->snd_una == tp->mtu_probe.probe_seq_start)
		{
			tcp_mtup_probe_failed(sk);
			/* Restores the reduction we did in tcp_mtup_probe() */
			tp->snd_cwnd++;
			tcp_simple_retransmit(sk);
			return;
		}

		/* Otherwise enter Recovery state */

		if (tcp_is_reno(tp))
			NET_INC_STATS_BH(LINUX_MIB_TCPRENORECOVERY);
		else
			NET_INC_STATS_BH(LINUX_MIB_TCPSACKRECOVERY);

		tp->high_seq = tp->snd_nxt;
		//tp->prior_ssthresh is reset here because we set it once again only if we have not received congestion notification. 
		tp->prior_ssthresh = 0;
		tp->undo_marker = tp->snd_una;
		//tp->retrans_out may be set while entering the recovery state in case we have undone from the loss state because of
		//duplicate ACKs generated as a result of an out-of-order segment from the window that got us into the congestion 
		//state. Or we may have exited the loss state on reception of a partial ACK from the original transmission, and we can 
		//catch DSACKs from this window now.
		tp->undo_retrans = tp->retrans_out;

		if (icsk->icsk_ca_state < TCP_CA_CWR) 
		{
			if (!(flag&FLAG_ECE))
			{
				//This is recorded so that we can revert to these values in case we are able to undo from this state (false
				//entry into congestion state by calling tcp_undo_cwr()). 
				tp->prior_ssthresh = tcp_current_ssthresh(sk);
			}

			// bring down the value of the slow - start threshold, which is standard practice. 
			tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
			//Call TCP_ECN_queue_cwr() to set the TCP_ECN_QUEUE_CWR flag, ensuring that we send out the CWR bit with the new 
			//data segment to inform the other end that we have a reduced congestion window.
			TCP_ECN_queue_cwr(tp);
		}

		tp->bytes_acked = 0;
		tp->snd_cwnd_cnt = 0;
		tcp_set_ca_state(sk, TCP_CA_Recovery);
	}

	//We are here if we have just entered the recovery state or we received a partial or duplicate ACK in the recovery state. 
	//In the next step we will see how we mark lost segments, and then we will learn how we select segments to be retransmitted

	//We call tcp_update_scoreboard() to update lost segments within the window in two cases:
	//1.
	//2.In the case where the head of the segment has timed out and tcp_head_timedout() returns TRUE
	if (do_lost || tcp_head_timedout(sk))
	{
	
		tcp_update_scoreboard(sk);
	}
		
	tcp_cwnd_down(sk, flag);
	//initiate retransmission of the segments marked as lost. We may also do forward retransmissions here.
	tcp_xmit_retransmit_queue(sk);
}

/* Read draft-ietf-tcplw-high-performance before mucking
 * with this code. (Supersedes RFC1323)
 */
static void tcp_ack_saw_tstamp(struct sock *sk, int flag)
{
	/* RTTM Rule: A TSecr value received in a segment is used to
	 * update the averaged RTT measurement only if the segment
	 * acknowledges some new data, i.e., only if it advances the
	 * left edge of the send window.
	 *
	 * See draft-ietf-tcplw-high-performance-00, section 3.3.
	 * 1998/04/10 Andrey V. Savochkin <saw@msu.ru>
	 *
	 * Changed: reset backoff as soon as we see the first valid sample.
	 * If we do not, we get strongly overestimated rto. With timestamps
	 * samples are accepted even from very old segments: f.e., when rtt=1
	 * increases to 8, we retransmit 5 times and after 8 seconds delayed
	 * answer arrives rto becomes 120 seconds! If at least one of segments
	 * in window is lost... Voila.	 			--ANK (010210)
	 */
	// Ê¹ÓÃÊ±¼ä´ÁÑ¡Ê±ÎÒÃÇÖªµÀÕâ¸öACKµÄ´¥·¢¶ÎµÄÈ·ÇÐ·¢ËÍÊ±¼äÎª£ºtp->rx_opt.rcv_tsecr£¬
	//ËùÒÔÎÒÃÇ¼ÆËãµÃµ½µÄRTT×ÜÊÇÕýÈ·µÄ£¬¶ø²»ÓÃÈ¥¿¼ÂÇ´¥·¢Õâ¸öACKµÄÊÇÔ­Ê¼°ü»¹ÊÇÖØ´«°ü
	struct tcp_sock *tp = tcp_sk(sk);
	const __u32 seq_rtt = tcp_time_stamp - tp->rx_opt.rcv_tsecr;
	tcp_rtt_estimator(sk, seq_rtt);
	tcp_set_rto(sk);
	inet_csk(sk)->icsk_backoff = 0;
	tcp_bound_rto(sk);
}

static void tcp_ack_no_tstamp(struct sock *sk, u32 seq_rtt, int flag)
{
	/* We don't have a timestamp. Can only use
	 * packets that are not retransmitted to determine
	 * rtt estimates. Also, we must not reset the
	 * backoff for rto until we get a non-retransmitted
	 * packet. This allows us to deal with a situation
	 * where the network delay has increased suddenly.
	 * I.e. Karn's algorithm. (SIGCOMM '87, p5.)
	 */

	//Ã»ÓÐÊ¹ÓÃÊ±¼ä´ÁÑ¡ÏîÈ·ÈÏµÄÊý¾Ý¶ÎÖÐ²»ÄÜ°üº¬ÖØ´«¹ýµÄ¶Î(FLAG_RETRANS_DATA_ACKED)¡£
    //ÒòÎªÎÒÃÇÎÞ·¨ÖªµÀÊÇÄÄ¸ö°ü£¬Ô­Ê¼°ü»¹ÊÇÖØ´«°ü´¥·¢ÁËÕâ¸öACK£¬Òò´ËÎÞ·¨È·¶¨´¥·¢°üµÄ·¢ËÍÊ±¼ä¡£
	if (flag & FLAG_RETRANS_DATA_ACKED)
		return;

	tcp_rtt_estimator(sk, seq_rtt);
	tcp_set_rto(sk);
	inet_csk(sk)->icsk_backoff = 0;
	tcp_bound_rto(sk);
}

static inline void tcp_ack_update_rtt(struct sock *sk, const int flag, const s32 seq_rtt)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	/* Note that peer MAY send zero echo. In this case it is ignored. (rfc1323) */
	if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr)
		tcp_ack_saw_tstamp(sk, flag);
	else if (seq_rtt >= 0)
		tcp_ack_no_tstamp(sk, seq_rtt, flag);
}

//This routine implements a congestion control algorithm during slow start and fast retransmission. 
static void tcp_cong_avoid(struct sock *sk, u32 ack, u32 in_flight, int good)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	icsk->icsk_ca_ops->cong_avoid(sk, ack, in_flight, good);
	tcp_sk(sk)->snd_cwnd_stamp = tcp_time_stamp;
}

/* Restart timer after forward progress on connection.
 * RFC2988 recommends to restart timer to now+rto.
 */
static void tcp_rearm_rto(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	//If we have acked all the data, the retransmit timer should be stopped.
	// Otherwise we should set the retransmit timer to the current value of RTO
	//for the next segment to be ACKed 

	//In the case where all the segments are ACKed, we remove retransmit timer .Otherwise we reset timer
	//This is the only place when we clear retransmit timer since we know that we are not waiting for any more ACKs
	if (!tp->packets_out)  
		inet_csk_clear_xmit_timer(sk, ICSK_TIME_RETRANS);
	else
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS, inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
}

/* If we get here, the whole TSO packet has not been acked. */
//»ñÈ¡TSO¶Î±»È·ÈÏµÄ×Ó¶ÎÊý
static u32 tcp_tso_acked(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 packets_acked;

	BUG_ON(!after(TCP_SKB_CB(skb)->end_seq, tp->snd_una));

	packets_acked = tcp_skb_pcount(skb);   	//tso¶Î×Ü¹²°üÀ¨¶ÎÊý 
	if (tcp_trim_head(sk, skb, tp->snd_una - TCP_SKB_CB(skb)->seq))
		return 0;
	packets_acked -= tcp_skb_pcount(skb);  //¼õÈ¥Î´È·ÈÏµÄ¶Î  

	if (packets_acked) 
	{
		BUG_ON(tcp_skb_pcount(skb) == 0);
		BUG_ON(!before(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq));
	}

	return packets_acked;	//·µ»ØÈ·ÈÏµÄ¶ÎÊý
}

/* Remove acknowledged frames from the retransmission queue. If our packet
 * is before the ack sequence we can discard it as it's confirmed to have
 * arrived at the other end.
 */
//  prior_snd_una      snd_una     snd_nxt
//--------|--------------|----------|-------
//´¦Àíprior_snd_unaµ½snd_unaÖ®¼ä±»È·ÈÏµÄ±¨ÎÄ¶Î
//ÎÊÌâ:
//1.reord
//2.tcp_update_reordering
static int tcp_clean_rtx_queue(struct sock *sk, s32 *seq_rtt_p, int prior_fackets)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct sk_buff *skb;
	u32 now = tcp_time_stamp;		 	// µ±Ç°Ê±¼ä£¬ÓÃÓÚ¼ÆËãRTT  
	int fully_acked = 1;				//±íÊ¾Êý¾Ý¶ÎÊÇ·ñÍêÈ«±»È·ÈÏ
	int flag = 0;
	int prior_packets = tp->packets_out;
	u32 cnt = 0;						//	/* ÀÛ¼Ó´ËACK¶ÎÈ·ÈÏµÄÊý¾ÝÁ¿*/ 
	u32 reord = tp->packets_out;
	s32 seq_rtt = -1;
	s32 ca_seq_rtt = -1;
	ktime_t last_ackt = net_invalid_timestamp();  //°Ñlast_acktÖÃÎª 0

	//±éÀúÖØ´«¶ÓÁÐ
	//±éÀúµ½snd_una¼´Í£Ö¹£¬Ò²¾ÍÊÇËµÈç¹ûsnd_unaÃ»¸üÐÂ£¬ÄÇÃ´Õâ¸öÑ­»·ÂíÉÏ¾ÍÍË³ö
	while ((skb = tcp_write_queue_head(sk)) && skb != tcp_send_head(sk))
	{
		struct tcp_skb_cb *scb = TCP_SKB_CB(skb);
		u32 end_seq;
		u32 packets_acked;
		u8 sacked = scb->sacked;

		/* Determine how many packets and what bytes were acked, tso and else */
		//tp->snd_unaÒÑ¾­ÊÇ¸üÐÂ¹ýµÄÁË£¬ËùÒÔ´Ó·¢ËÍ¶ÓÁÐÍ·µ½snd_una¾ÍÊÇ´ËACKÈ·ÈÏµÄÊý¾ÝÁ¿
		if (after(scb->end_seq, tp->snd_una)) 
		{
			/* Èç¹ûÃ»ÓÐÊ¹ÓÃTSO£¬»ò seq >= snd_una£¬ÄÇÃ´¾ÍÍË³ö±éÀú*/  
			//¸Ã¶ÎÃ»ÓÐ±»È·ÈÏ
			if (tcp_skb_pcount(skb) == 1 || !after(tp->snd_una, scb->seq))
				break;

			/* Èç¹ûÖ»È·ÈÏÁËTSO¶ÎÖÐµÄÒ»²¿·Ö£¬Ôò½ØµôÈ·ÈÏµÄ²¿·Ö£¬²¢Í³¼ÆÈ·ÈÏÁË¶àÉÙ¶Î*/  
			packets_acked = tcp_tso_acked(sk, skb);
			if (!packets_acked)   /* ´¦Àí³ö´í */
				break;

			fully_acked = 0;  	/* ±íÊ¾Ã»ÓÐÈ·ÈÏÍêTSO¶Î*/
			end_seq = tp->snd_una;
		} 
		else
		{
			packets_acked = tcp_skb_pcount(skb);  /* Í³¼ÆÈ·ÈÏ¶ÎµÄ¸öÊý*/ 
			end_seq = scb->end_seq;
		}

		/* MTU probing checks */
		if (fully_acked && icsk->icsk_mtup.probe_size && !after(tp->mtu_probe.probe_seq_end, scb->end_seq)) 
		{
			tcp_mtup_probe_success(sk, skb);
		}

		if (sacked)
		{
			 /* Èç¹û´Ë¶Î±»ÖØ´«¹ý*/  
			 //We Check if the segemnt was ever retransmitted?
			if (sacked & TCPCB_RETRANS) 
			{
				//TCPCB_SACKED_RETRANS±êÖ¾Ê²Ã´Ê±ºò»á±»È¥³ýå //???
				if (sacked & TCPCB_SACKED_RETRANS)  	// Èç¹ûÖ®Ç°ÖØ´«¹ý£¬&& Ö®Ç°»¹Ã»ÊÕµ½»Ø¸´ 
					tp->retrans_out -= packets_acked;  /* ¸üÐÂÍøÂçÖÐÖØ´«ÇÒÎ´È·ÈÏ¶ÎµÄÊýÁ¿*/  

				//±êÊ¶´ËACK¶ÎÈ·ÈÏÁËÔø¾­±»ÖØ´«¹ýµÄÊý¾Ý
				//ÎªºÎ×ö´Ë±ê¼Ç(×÷ÓÃ)å???
				flag |= FLAG_RETRANS_DATA_ACKED;

				//we don't calculate rtt for retransmitted segment
				ca_seq_rtt = -1;
				seq_rtt = -1;

				//ÓÃÓÚF-RTO
				if ((flag & FLAG_DATA_ACKED) || (packets_acked > 1))  
					flag |= FLAG_NONHEAD_RETRANS_ACKED;
			}
			else  /* Èç¹û´Ë¶ÎÃ»ÓÐ±»ÖØ´«¹ý*/  
			{
				//if the segment was never retransmitted and RTT is not yet recorded, we calculate RTT 
				//based on the current timestamp and the time recorded when the segment was transmitted.
				ca_seq_rtt = now - scb->when;   
				last_ackt = skb->tstamp;			/* »ñÈ¡´ËskbµÄ·¢ËÍÊ±¼ä£¬¿ÉÒÔ¾«È·µ½ÄÉÃë£¡*/  
				if (seq_rtt < 0) 
				{
					seq_rtt = ca_seq_rtt;
				}
				
				/* Èç¹ûSACK¿éÖÐÓÐ¿Õ¶´£¬ÄÇÃ´±£´æÆäÖÐÐòºÅ×îÐ¡ºÅµÄ */   
				//???
				if (!(sacked & TCPCB_SACKED_ACKED))
					reord = min(cnt, reord);
			}

			 /* Èç¹ûskbÖ®Ç°ÊÇ´øÓÐSACK±êÖ¾ */  
			if (sacked & TCPCB_SACKED_ACKED)  
				tp->sacked_out -= packets_acked;  /* ¸üÐÂsacked_out */ 

			/* Èç¹ûskbÖ®Ç°ÊÇ´øÓÐLOST±êÖ¾ */  
			if (sacked & TCPCB_LOST)
				tp->lost_out -= packets_acked;  /* ¸üÐÂlost_out */ 

			//If this segment is marked to contain an urgent pointer,
			//we check if the urgent mode is set. If set, we check if the segment
			//covers the urgent pointer . If both are true, an urgent byte is
			//ACKed and we unset the urgent mode.
			if ((sacked & TCPCB_URG) && tp->urg_mode && !before(end_seq, tp->snd_up))
				tp->urg_mode = 0;
		} 
		else  
		{	//neither retransmitted nor SACKed, and neither was marked lost
		
			//¼ÆËãRTT
			ca_seq_rtt = now - scb->when;
			last_ackt = skb->tstamp;
			if (seq_rtt < 0)
			{
				seq_rtt = ca_seq_rtt;
			}
			
			reord = min(cnt, reord);
		}
		
		tp->packets_out -= packets_acked;  /* ¸üÐÂpackets_out */  
		cnt += packets_acked;   			/* ÀÛ¼Ó´ËACKÈ·ÈÏµÄÊý¾ÝÁ¿*/  

		/* Initial outgoing SYN's get put onto the write_queue
		 * just like anything else we transmit.  It is not
		 * true data, and if we misinform our callers that
		 * this ACK acks real data, we will erroneously exit
		 * connection startup slow start one packet too
		 * quickly.  This is severely frowned upon behavior.
		 */
		if (!(scb->flags & TCPCB_FLAG_SYN)) 
		{
			flag |= FLAG_DATA_ACKED;  	/* È·ÈÏÁËÐÂµÄÊý¾Ý */
		} 
		else
		{
			flag |= FLAG_SYN_ACKED;  	/* È·ÈÏÁËSYN¶Î */  
			tp->retrans_stamp = 0;   	/* Clear the stamp of the first SYN */  
		}

		if (!fully_acked)  /* Èç¹ûTSO¶ÎÃ»±»ÍêÈ«È·ÈÏ£¬Ôòµ½´ËÎªÖ¹*/
			break;

		tcp_unlink_write_queue(skb, sk);  /* ´Ó·¢ËÍ¶ÓÁÐÉÏÒÆ³ýskb */  
		sk_stream_free_skb(sk, skb);		/* É¾³ýskbµÄÄÚ´æ¶ÔÏó*/  
		tcp_clear_all_retrans_hints(tp);
	}


	 /* Èç¹û´ËACKÈ·ÈÏÁËÐÂÊý¾Ý£¬Ê¹snd_unaÇ°½øÁË*/  
	if (flag & FLAG_ACKED)
	{
		//The number of segments ACKed is calculated based on number of packets 
		//transmitted (tp->packets_out) before and after arrival of the ACK
		u32 pkts_acked = prior_packets - tp->packets_out;
		const struct tcp_congestion_ops *ca_ops = inet_csk(sk)->icsk_ca_ops;

		/* ¸üÐÂsrtt¡¢RTOµÈRTTÏà¹Ø±äÁ¿*/  
		//estimate RTO based on either TCP timestamp option or the
		//new rtt calculated above
		tcp_ack_update_rtt(sk, flag, seq_rtt);
		
		//We need to reset a retransmit timer on each ACK we receive that advances a send window
		/* ÖØÖÃ³¬Ê±ÖØ´«¶¨Ê±Æ÷*/  
		tcp_rearm_rto(sk);  

		if (tcp_is_reno(tp)) 
		{
			/* RenoÄ£ÄâSACK´¦Àí£¬¸üÐÂtp->sacked_out¡£ 
             * Èç¹û¼ì²âµ½ÂÒÐò£¬¸üÐÂtp->reordering¡£ 
             */  
			tcp_remove_reno_sacks(sk, pkts_acked);
		} 
		else 
		{
		/* Non-retransmitted hole got filled? That's reordering¡£ 
             * Èç¹ûÖ®Ç°Ã»ÓÐSACK£¬prior_facketsÎª0£¬²»»á¸üÐÂ¡£ 
             */  
			/* Non-retransmitted hole got filled? That's reordering */
			if (reord < prior_fackets)
				tcp_update_reordering(sk, tp->fackets_out - reord, 0); /* ¸üÐÂÂÒÐò¶ÓÁÐ´óÐ¡*/  
		}

		tp->fackets_out -= min(pkts_acked, tp->fackets_out);   /* ¸üÐÂfackets_out */  
		/* hint's skb might be NULL but we don't need to care */
		tp->fastpath_cnt_hint -= min_t(u32, pkts_acked, tp->fastpath_cnt_hint);

		//Èç¹û¶¨ÒåÁËpkts_acked()¹³×Ó
		if (ca_ops->pkts_acked)
		{
			s32 rtt_us = -1;

			/* Is the ACK triggering packet unambiguous? */  //È·ÈÏÁË·ÇÖØ´«µÄÊý¾Ý¶Î
			if (!(flag & FLAG_RETRANS_DATA_ACKED)) 
			{
				/* High resolution needed and available? */
				if (ca_ops->flags & TCP_CONG_RTT_STAMP && !ktime_equal(last_ackt, net_invalid_timestamp()))
					rtt_us = ktime_us_delta(ktime_get_real(), last_ackt);  //¸ß¾«È·¶ÈµÄRTT²âÁ¿£¬¿ÉÒÔ¾«È·µ½Î¢Ãë£¡ 
				else if (ca_seq_rtt > 0)   /* ÆÕÍ¨²âÁ¿£¬¾«È·µ½ºÁÃë£¬ÔÙ×ªÎªÎ¢Ãë*/ 
					rtt_us = jiffies_to_usecs(ca_seq_rtt);
			}

			ca_ops->pkts_acked(sk, pkts_acked, rtt_us);
		}
	}

#if FASTRETRANS_DEBUG > 0
	BUG_TRAP((int)tp->sacked_out >= 0);
	BUG_TRAP((int)tp->lost_out >= 0);
	BUG_TRAP((int)tp->retrans_out >= 0);
	if (!tp->packets_out && tcp_is_sack(tp)) 
	{
		icsk = inet_csk(sk);
		if (tp->lost_out) {
			printk(KERN_DEBUG "Leak l=%u %d\n",
			       tp->lost_out, icsk->icsk_ca_state);
			tp->lost_out = 0;
		}
		if (tp->sacked_out) 
		{
			printk(KERN_DEBUG "Leak s=%u %d\n", tp->sacked_out, icsk->icsk_ca_state);
			tp->sacked_out = 0;
		}
		if (tp->retrans_out) {
			printk(KERN_DEBUG "Leak r=%u %d\n",
			       tp->retrans_out, icsk->icsk_ca_state);
			tp->retrans_out = 0;
		}
	}
#endif
	*seq_rtt_p = seq_rtt;
	return flag;
}

static void tcp_ack_probe(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	/* Was it a usable window open? */

	if (!after(TCP_SKB_CB(tcp_send_head(sk))->end_seq,
		   tp->snd_una + tp->snd_wnd)) {
		icsk->icsk_backoff = 0;
		inet_csk_clear_xmit_timer(sk, ICSK_TIME_PROBE0);
		/* Socket must be waked up by subsequent tcp_data_snd_check().
		 * This function is not for random using!
		 */
	} else {
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
					  min(icsk->icsk_rto << icsk->icsk_backoff, TCP_RTO_MAX),
					  TCP_RTO_MAX);
	}
}

static inline int tcp_ack_is_dubious(const struct sock *sk, const int flag)
{
	//±íÊ¾½ÓÊÕµ½µÄACKÊÇÖØ¸´µÄ
	//½ÓÊÕµ½SACK¿é»òÏÔÊ¾ÓµÈûÍ¨Öª
	//µ±Ç°ÓµÈû×´Ì¬²»ÎªOpen£¬ÒÑ¾­½øÈëÁËÓµÈû×´Ì¬
	return (!(flag & FLAG_NOT_DUP) || (flag & FLAG_CA_ALERT) || inet_csk(sk)->icsk_ca_state != TCP_CA_Open);
}

static inline int tcp_may_raise_cwnd(const struct sock *sk, const int flag)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	return (!(flag & FLAG_ECE) || tp->snd_cwnd < tp->snd_ssthresh) &&
		!((1 << inet_csk(sk)->icsk_ca_state) & (TCPF_CA_Recovery | TCPF_CA_CWR));
}

/* Check that window update is acceptable.
 * The function assumes that snd_una<=ack<=snd_next.
 */
static inline int tcp_may_update_window(const struct tcp_sock *tp, const u32 ack, const u32 ack_seq, const u32 nwin)
{
	//RFC 793, p. 72
	//1.È·ÈÏÐòºÅÔÚ·¢ËÍ´°¿ÚµÄsnd_unaºÍsnd_nxtÖ®¼ä
	//2.ACK¶ÎµÄÐòºÅÊÇ×îÐÂµÄ
	//3.½ÓÊÕµ½ÖØ¸´ACK£¬²¢ÇÒ½ÓÊÕ·½µÄ½ÓÊÕ´°¿Ú´óÓÚµ±Ç°·¢ËÍ·½µÄ·¢ËÍ´°¿Ú(¿ÉÄÜÊÇ´øÓÐÊý¾Ý¶ÎµÄTCP¶Î)
	return (after(ack, tp->snd_una) || after(ack_seq, tp->snd_wl1) || (ack_seq == tp->snd_wl1 && nwin > tp->snd_wnd));
}

/* Update our send window.
 *
 * Window update algorithm, described in RFC793/RFC1122 (used in linux-2.2
 * and in FreeBSD. NetBSD's one is even worse.) is wrong.
 */

//¸üÐÂ·¢ËÍ´°¿Ú
//skb -- ½ÓÊÕµ½µÄACK¶Î
//ack -- ACK¶ÎÖÐµÄÐòºÅ
//ack_seq -- ACK¶ÎÖÐµÄÈ·ÈÏÐòºÅ
static int tcp_ack_update_window(struct sock *sk, struct sk_buff *skb, u32 ack, u32 ack_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int flag = 0;

	//´ÓTCPÊ×²¿ÖÐ»ñÈ¡½ÓÊÕ·½µÄ½ÓÊÕ´°¿Ú´óÐ¡£¬²¢ÓÉ´°¿ÚÀ©´óÒò×Ó¼ÆËã³ö½ÓÊÕ´°¿ÚµÄ×Ö½ÚÊý
	//×¢Òâ:ÔÚSYN»òSYN/ACK±¨ÎÄ±¾ÉíµÄ´°¿Ú×Ö¶ÎÊ¼ÖÕ²»×öÈÎºÎµÄÀ©´ó
	u32 nwin = ntohs(tcp_hdr(skb)->window);
	if (likely(!tcp_hdr(skb)->syn))
		nwin <<= tp->rx_opt.snd_wscale;

	//ÅÐ¶ÏÊÇ·ñÐèÒª¸üÐÂ·¢ËÍ´°¿Ú
	if (tcp_may_update_window(tp, ack, ack_seq, nwin))
	{
		flag |= FLAG_WIN_UPDATE;
		
		tcp_update_wl(tp, ack, ack_seq);

		if (tp->snd_wnd != nwin) 
		{
			tp->snd_wnd = nwin;

			/* Note, it is the only place, where fast path is recovered for sending TCP. */
			//ÓÉÓÚÓÃÓÚÊ×²¿Ô¤²âµÄ±ê¼ÇÓë½ÓÊÕ´°¿Ú´óÐ¡ÓÐ¹Ø£¬Òò´ËÐèÒªÇåÁãÔ¤²â±êÖ¾£¬
			//È»ºóµ÷ÓÃtcp_fast_path_check£¬ÔÚÂú×ãÌõ¼þµÄÇé¿öÏÂÖØÐÂ¼ÆËãÊ×²¿Ô¤²â±êÖ¾
			//We do it here because the window has changed and if are already in FAST path, prediction flag
			//needs to be initialized as it takes the window into account.
			tp->pred_flags = 0;
			tcp_fast_path_check(sk);

			if (nwin > tp->max_window)
			{
				tp->max_window = nwin;
				tcp_sync_mss(sk, inet_csk(sk)->icsk_pmtu_cookie);
			}
		}
	}

	tp->snd_una = ack;

	return flag;
}

/* A very conservative spurious RTO response algorithm: reduce cwnd and
 * continue in congestion avoidance.
 */
static void tcp_conservative_spur_to_response(struct tcp_sock *tp)
{
	tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_ssthresh);
	tp->snd_cwnd_cnt = 0;
	tp->bytes_acked = 0;
	TCP_ECN_queue_cwr(tp);
	tcp_moderate_cwnd(tp);
}

/* A conservative spurious RTO response algorithm: reduce cwnd using
 * rate halving and continue in congestion avoidance.
 */
static void tcp_ratehalving_spur_to_response(struct sock *sk)
{
	tcp_enter_cwr(sk, 0);
}

static void tcp_undo_spur_to_response(struct sock *sk, int flag)
{
	if (flag&FLAG_ECE)
		tcp_ratehalving_spur_to_response(sk);
	else
		tcp_undo_cwr(sk, 1);
}

/* F-RTO spurious RTO detection algorithm (RFC4138)
 *
 * F-RTO affects during two new ACKs following RTO (well, almost, see inline
 * comments). State (ACK number) is kept in frto_counter. When ACK advances
 * window (but not to or beyond highest sequence sent before RTO):
 *   On First ACK,  send two new segments out.
 *   On Second ACK, RTO was likely spurious. Do spurious response (response
 *                  algorithm is not part of the F-RTO detection algorithm
 *                  given in RFC4138 but can be selected separately).
 * Otherwise (basically on duplicate ACK), RTO was (likely) caused by a loss
 * and TCP falls back to conventional RTO recovery. F-RTO allows overriding
 * of Nagle, this is done using frto_counter states 2 and 3, when a new data
 * segment of any size sent during F-RTO, state 2 is upgraded to 3.
 *
 * Rationale: if the RTO was spurious, new ACKs should arrive from the
 * original window even after we transmit two new data segments.
 *
 * SACK version:
 *   on first step, wait until first cumulative ACK arrives, then move to
 *   the second step. In second step, the next ACK decides.
 *
 * F-RTO is implemented (mainly) in four functions:
 *   - tcp_use_frto() is used to determine if TCP is can use F-RTO
 *   - tcp_enter_frto() prepares TCP state on RTO if F-RTO is used, it is
 *     called when tcp_use_frto() showed green light
 *   - tcp_process_frto() handles incoming ACKs during F-RTO algorithm
 *   - tcp_enter_frto_loss() is called if there is not enough evidence
 *     to prove that the RTO is indeed spurious. It transfers the control
 *     from F-RTO to the conventional RTO recovery
 */
static int tcp_process_frto(struct sock *sk, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_verify_left_out(tp);

	/* Duplicate the behavior from Loss state (fastretrans_alert) */
	if (flag&FLAG_DATA_ACKED)
		inet_csk(sk)->icsk_retransmits = 0;

	if ((flag & FLAG_NONHEAD_RETRANS_ACKED) ||
	    ((tp->frto_counter >= 2) && (flag & FLAG_RETRANS_DATA_ACKED)))
		tp->undo_marker = 0;

	if (!before(tp->snd_una, tp->frto_highmark)) {
		tcp_enter_frto_loss(sk, (tp->frto_counter == 1 ? 2 : 3), flag);
		return 1;
	}

	if (!IsSackFrto() || tcp_is_reno(tp)) {
		/* RFC4138 shortcoming in step 2; should also have case c):
		 * ACK isn't duplicate nor advances window, e.g., opposite dir
		 * data, winupdate
		 */
		if (!(flag&FLAG_ANY_PROGRESS) && (flag&FLAG_NOT_DUP))
			return 1;

		if (!(flag&FLAG_DATA_ACKED)) {
			tcp_enter_frto_loss(sk, (tp->frto_counter == 1 ? 0 : 3),
					    flag);
			return 1;
		}
	} else {
		if (!(flag&FLAG_DATA_ACKED) && (tp->frto_counter == 1)) {
			/* Prevent sending of new data. */
			tp->snd_cwnd = min(tp->snd_cwnd,
					   tcp_packets_in_flight(tp));
			return 1;
		}

		if ((tp->frto_counter >= 2) &&
		    (!(flag&FLAG_FORWARD_PROGRESS) ||
		     ((flag&FLAG_DATA_SACKED) && !(flag&FLAG_ONLY_ORIG_SACKED)))) {
			/* RFC4138 shortcoming (see comment above) */
			if (!(flag&FLAG_FORWARD_PROGRESS) && (flag&FLAG_NOT_DUP))
				return 1;

			tcp_enter_frto_loss(sk, 3, flag);
			return 1;
		}
	}

	if (tp->frto_counter == 1) {
		/* tcp_may_send_now needs to see updated state */
		tp->snd_cwnd = tcp_packets_in_flight(tp) + 2;
		tp->frto_counter = 2;

		if (!tcp_may_send_now(sk))
			tcp_enter_frto_loss(sk, 2, flag);

		return 1;
	} else {
		switch (sysctl_tcp_frto_response) {
		case 2:
			tcp_undo_spur_to_response(sk, flag);
			break;
		case 1:
			tcp_conservative_spur_to_response(tp);
			break;
		default:
			tcp_ratehalving_spur_to_response(sk);
			break;
		}
		tp->frto_counter = 0;
		tp->undo_marker = 0;
		NET_INC_STATS_BH(LINUX_MIB_TCPSPURIOUSRTOS);
	}
	return 0;
}

/* This routine deals with incoming acks, but not outgoing ones. */
static int tcp_ack(struct sock *sk, struct sk_buff *skb, int flag)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 prior_snd_una = tp->snd_una;		/* ´ËACKÖ®Ç°µÄsnd_una */  	
	u32 ack_seq = TCP_SKB_CB(skb)->seq;		/* ´ËACKµÄ¿ªÊ¼ÐòºÅ */
	u32 ack = TCP_SKB_CB(skb)->ack_seq;		/* ´ËACKµÄÈ·ÈÏÐòºÅ */ 
	u32 prior_in_flight;
	u32 prior_fackets;
	s32 seq_rtt;
	int prior_packets;
	int frto_cwnd = 0;

	/* If the ack is newer than sent or older than previous acks then we can probably ignore it. */
	if (after(ack, tp->snd_nxt))
		goto uninteresting_ack;

	if (before(ack, prior_snd_una))
		goto old_ack;

	if (after(ack, prior_snd_una))
		flag |= FLAG_SND_UNA_ADVANCED;


	////ÊÇ·ñÉèÖÃtcp_abc£¬ÓÐÉèÖÃµÄ»°£¬ËµÃ÷ÎÒÃÇ²»ÐèÒªÃ¿¸öackÈ·ÈÏ¶¼ÒªÓµÈû±ÜÃâ£¬Òò´ËÎÒÃÇÐèÒª¼ÆËãÒÑ¾­ack(È·ÈÏ)µÄ×Ö½ÚÊý¡£
	//  /* tcp_abcÑ¡Ïî´¦Àí£¬ÀÛ¼ÓÕâ¸öACKÈ·ÈÏµÄ×Ö½ÚÊý */
	if (sysctl_tcp_abc) 
	{
		if (icsk->icsk_ca_state < TCP_CA_CWR)
			tp->bytes_acked += ack - prior_snd_una;
		else if (icsk->icsk_ca_state == TCP_CA_Loss)
			/* we assume just one segment left network */
			tp->bytes_acked += min(ack - prior_snd_una, tp->mss_cache);
	}

	prior_fackets = tp->fackets_out;
	prior_in_flight = tcp_packets_in_flight(tp);

	 /* Èç¹û´¦ÓÚ¿ìËÙÂ·¾¶ÖÐ*/  
	if (!(flag & FLAG_SLOWPATH) && after(ack, prior_snd_una))
	{
		/* Window is constant, pure forward advance.
		 * No more checks are required.
		 * Note, we use the fact that SND.UNA>=SND.WL2.
		 */
		tcp_update_wl(tp, ack, ack_seq);  ///*¼ÇÂ¼¸üÐÂ·¢ËÍ´°¿ÚµÄACK¶ÎÐòºÅ*
		tp->snd_una = ack;					//¸üÐÂ·¢ËÍ´°¿Ú×ó¶Ë
		flag |= FLAG_WIN_UPDATE;			//ÉèÖÃ·¢ËÍ´°¿Ú¸üÐÂ±êÖ¾

		tcp_ca_event(sk, CA_EVENT_FAST_ACK);	//¿ìËÙÂ·¾¶ÓµÈûÊÂ¼þ¹³×Ó

		NET_INC_STATS_BH(LINUX_MIB_TCPHPACKS);
	}
	else  /* ½øÈëÂýËÙÂ·¾¶ */  
	{
		//ÅÐ¶ÏACK¶ÎÖÐÊÇ·ñÓÐÊý¾Ý¸ºÔØ£¬Èç¹ûÓÐÌí¼ÓFLAG_DATA±ê¼Ç
		if (ack_seq != TCP_SKB_CB(skb)->end_seq)
			flag |= FLAG_DATA;		
		else 
			NET_INC_STATS_BH(LINUX_MIB_TCPPUREACKS);

		//¸üÐÂ·¢ËÍ´°¿Ú£¬Í¬Ê±Ìí¼Ó¸üÐÂ·¢ËÍ´°¿Úºó»ñÈ¡µÄ±êÖ¾
		flag |= tcp_ack_update_window(sk, skb, ack, ack_seq);  

		//Èç¹û½ÓÊÕµÄ¶ÎÖÐ´æÔÚSACKÑ¡Ïî£¬±ê¼ÇÖØ´«¶ÓÁÐÖÐSKBµÄ¼Ç·ÖÅÆ×´Ì¬
		if (TCP_SKB_CB(skb)->sacked)  
			flag |= tcp_sacktag_write_queue(sk, skb, prior_snd_una);

		//¼ì²âACK¶ÎÖÐÊÇ·ñ´æÔÚECE±êÖ¾£¬Èç¹ûÓÐÌí¼ÓFLAG_ECE±êÖ¾
		if (TCP_ECN_rcv_ecn_echo(tp, tcp_hdr(skb)))   //Â·ÓÉÆ÷Í¨Öª¶ª°ü£¬ÖÃÉÏeceÎ»
			flag |= FLAG_ECE;

		//Í¨ÖªÓµÈû¿ØÖÆËã·¨Ä£¿é±¾´ÎACKÊÇÂýËÙÂ·¾¶£¬ÈçÓÐ±ØÒªÔò×öÏìÓ¦´¦Àí
		tcp_ca_event(sk, CA_EVENT_SLOW_ACK);  		
	}

	/* We passed data and got it acked, remove any soft error
	 * log. Something worked...
	 */
	sk->sk_err_soft = 0;
	
	//ÉèÖÃ×î½üÒ»´ÎÊÕµ½ACKµÄÊ±¼ä´Á
	tp->rcv_tstamp = tcp_time_stamp;   

	//¼ì²éÊÇ·ñÓÐ·¢ËÍÇÒÎ´È·ÈÏµÄ¶Î, Èç¹ûÃ»ÓÐÌø×ªµ½no_queue´¦Àí
	prior_packets = tp->packets_out;
	if (!prior_packets)				
		goto no_queue;				/* ³ÖÐø¶¨Ê±Æ÷´¦Àí*/  

	/* See if we can take anything off of the retransmit queue. */
	//É¾³ýÖØ´«¶ÓÁÐÖÐÒÑ¾­È·ÈÏµÄÊý¾Ý¶Î£¬²¢½øÐÐÊ±ÑÓ²ÉÑù¡£ 
	flag |= tcp_clean_rtx_queue(sk, &seq_rtt, prior_fackets);

	/* ´¦ÓÚFRTO´¦ÀíÖÐ£¬frto_counterµÄÈ¡ÖµÎª1»ò2*/  
	if (tp->frto_counter)
		frto_cwnd = tcp_process_frto(sk, flag);		/* ÅÐ¶ÏRTOÊÇ·ñÎªÕæµÄ*/  
	
	/* Guarantee sacktag reordering detection against wrap-arounds */
	if (before(tp->frto_highmark, tp->snd_una))
		tp->frto_highmark = 0;

	//¸ù¾ÝACKµÄÃ÷È·Óë·ñ£¬¸üÐÂÓµÈû´°¿Ú£¬½øÐÐÓµÈû¿ØÖÆ

	//¸ù¾ÝACK¶ÎÅÐ¶ÏÎÒÃÇÊÇ·ñ½øÈëÓµÈû×´Ì¬(ÊÕµ½ÓµÈûÐÅºÅ£¬²ì¾õµ½ÓµÈû)£¬»òÕßÒÑ¾­´¦ÓÚÓµÈû×´Ì¬¡£
	if (tcp_ack_is_dubious(sk, flag)) 
	{

        /* ÔÚÕâÖÖÌõ¼þÏÂÈç¹ûÏë½øÐÐÓµÈû±ÜÃâ£¬±ØÐë·ûºÏ£º 
         * 1. ´ËACKÈ·ÈÏÁËÐÂµÄÊý¾Ý 
         * 2. ²»ÄÜ´¦ÓÚFRTO×´Ì¬ 
         * 3. ´¦ÓÚDisorder»òLoss×´Ì¬ 
          */  
		/* Advance CWND, if state allows this. */
		if ((flag & FLAG_DATA_ACKED) && !frto_cwnd && tcp_may_raise_cwnd(sk, flag))
			tcp_cong_avoid(sk, ack, prior_in_flight, 0);  /* ÓµÈû´°¿ÚµÄµ÷½Ú*/ 
		 /* ÕâÀï½øÈëTCPµÄÓµÈû×´Ì¬»ú£¬´¦ÀíÏà¹ØÓµÈû×´Ì¬*/  
		tcp_fastretrans_alert(sk, prior_packets - tp->packets_out, flag);
	}
	else 
	{	/* ÖÁÉÙËµÃ÷ACKÔÚOpenÌ¬*/  
	 /* ACK²»ÊÇ¿ÉÒÉµÄ£¬Èç¹ûACKÈ·ÈÏÁËÐÂµÄÊý¾Ý£¬ÇÒ²»ÊÇfrto£¬Ôò½øÐÐÓµÈû±ÜÃâ*/  
	
		if ((flag & FLAG_DATA_ACKED) && !frto_cwnd)
			tcp_cong_avoid(sk, ack, prior_in_flight, 1);
	}

	/* Èç¹ûACKÈ·ÈÏÁËÐÂµÄ¶Î(ÐÂµÄÊý¾Ý¶Î¡¢SYN¶Î¡¢SACK¶Î£¬»òÕß½ÓÊÕµ½µÄACK²»ÊÇÖØ¸´µÄ£¬ 
     * ÔòÈ·ÈÏ¸Ã´«Êä¿ØÖÆ¿éµÄÊä³öÂ·ÓÉ»º´æÏîÊÇÓÐÐ§µÄ¡£ 
     */  
	if ((flag & FLAG_FORWARD_PROGRESS) || !(flag&FLAG_NOT_DUP))
		dst_confirm(sk->sk_dst_cache);

	return 1;

no_queue:
	icsk->icsk_probes_out = 0;

	/* If this ack opens up a zero window, clear backoff.  It was
	 * being used to time the probes, and is probably far higher than
	 * it needs to be for normal retransmission.
	 */
	if (tcp_send_head(sk))  /* Èç¹ûÓÐÊý¾ÝÒª·¢ËÍ*/  
		tcp_ack_probe(sk); 	/* ³ÖÐø¶¨Ê±Æ÷´¦Àí*/  
	return 1;

old_ack:
	/* Èç¹û´ËACKÒÑ¾­È·ÈÏ¹ý£¬ÇÒ´øÓÐSACKÑ¡ÏîµÄÐÅÏ¢*/  
	if (TCP_SKB_CB(skb)->sacked)
		/* ÖØÐÂ±êÖ¾¸÷¸ö¶ÎµÄ¼Ç·ÖÅÆ*/  
		tcp_sacktag_write_queue(sk, skb, prior_snd_una);

uninteresting_ack:
	SOCK_DEBUG(sk, "Ack %u out of %u:%u\n", ack, tp->snd_una, tp->snd_nxt);
	return 0;
}


/* Look for tcp options. Normally only called on SYN and SYNACK packets.
 * But, this can also be called on packets in the established flow when
 * the fast version below fails.
 */
void tcp_parse_options(struct sk_buff *skb, struct tcp_options_received *opt_rx, int estab)
{
	unsigned char *ptr;
	struct tcphdr *th = tcp_hdr(skb);
	int length=(th->doff*4)-sizeof(struct tcphdr);

	ptr = (unsigned char *)(th + 1);
	opt_rx->saw_tstamp = 0;

	while (length > 0) 
	{
		int opcode=*ptr++;
		int opsize;

		switch (opcode)
		{
			case TCPOPT_EOL:
				return;
			case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
				length--;
				continue;
			default:
				opsize=*ptr++;
				if (opsize < 2) /* "silly options" */
					return;
				if (opsize > length)
					return;	/* don't parse partial options */
				switch (opcode) 
				{
				case TCPOPT_MSS:
					if (opsize==TCPOLEN_MSS && th->syn && !estab) 
					{
						u16 in_mss = ntohs(get_unaligned((__be16 *)ptr));
						if (in_mss) 
						{
							if (opt_rx->user_mss && opt_rx->user_mss < in_mss)
								in_mss = opt_rx->user_mss;
							opt_rx->mss_clamp = in_mss;
						}
					}
					break;
				case TCPOPT_WINDOW:
					if (opsize==TCPOLEN_WINDOW && th->syn && !estab)
						if (sysctl_tcp_window_scaling) 
						{
							__u8 snd_wscale = *(__u8 *) ptr;
							opt_rx->wscale_ok = 1;
							if (snd_wscale > 14) {
								if (net_ratelimit())
									printk(KERN_INFO "tcp_parse_options: Illegal window "
									       "scaling value %d >14 received.\n",
									       snd_wscale);
								snd_wscale = 14;
							}
							opt_rx->snd_wscale = snd_wscale;
						}
					break;
				case TCPOPT_TIMESTAMP:
					if (opsize==TCPOLEN_TIMESTAMP) {
						if ((estab && opt_rx->tstamp_ok) ||
						    (!estab && sysctl_tcp_timestamps)) {
							opt_rx->saw_tstamp = 1;
							opt_rx->rcv_tsval = ntohl(get_unaligned((__be32 *)ptr));
							opt_rx->rcv_tsecr = ntohl(get_unaligned((__be32 *)(ptr+4)));
						}
					}
					break;
				case TCPOPT_SACK_PERM:
					if (opsize==TCPOLEN_SACK_PERM && th->syn && !estab) 
					{
						if (sysctl_tcp_sack) 
						{
							opt_rx->sack_ok = 1;
							tcp_sack_reset(opt_rx);
						}
					}
					break;

				case TCPOPT_SACK:
					if ((opsize >= (TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK)) &&
					   !((opsize - TCPOLEN_SACK_BASE) % TCPOLEN_SACK_PERBLOCK) &&
					   opt_rx->sack_ok) {
						TCP_SKB_CB(skb)->sacked = (ptr - 2) - (unsigned char *)th;
					}
					break;
#ifdef CONFIG_TCP_MD5SIG
				case TCPOPT_MD5SIG:
					/*
					 * The MD5 Hash has already been
					 * checked (see tcp_v{4,6}_do_rcv()).
					 */
					break;
#endif
				}

				ptr+=opsize-2;
				length-=opsize;
		}
	}
}

/* Fast parse options. This hopes to only see timestamps.
 * If it is wrong it falls back on tcp_parse_options().
 */
static int tcp_fast_parse_options(struct sk_buff *skb, struct tcphdr *th, struct tcp_sock *tp)
{
	if (th->doff == sizeof(struct tcphdr)>>2) 
	{
		tp->rx_opt.saw_tstamp = 0;
		return 0;
	}
	else if (tp->rx_opt.tstamp_ok && th->doff == (sizeof(struct tcphdr)>>2)+(TCPOLEN_TSTAMP_ALIGNED>>2)) 
	{
		__be32 *ptr = (__be32 *)(th + 1);
		if (*ptr == htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) | (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP))
		{
			tp->rx_opt.saw_tstamp = 1;
			++ptr;
			tp->rx_opt.rcv_tsval = ntohl(*ptr);
			++ptr;
			tp->rx_opt.rcv_tsecr = ntohl(*ptr);
			return 1;
		}
	}
	tcp_parse_options(skb, &tp->rx_opt, 1);
	return 1;
}

static inline void tcp_store_ts_recent(struct tcp_sock *tp)
{
	tp->rx_opt.ts_recent = tp->rx_opt.rcv_tsval;
	tp->rx_opt.ts_recent_stamp = get_seconds();
}

static inline void tcp_replace_ts_recent(struct tcp_sock *tp, u32 seq)
{
	if (tp->rx_opt.saw_tstamp && !after(seq, tp->rcv_wup)) {
		/* PAWS bug workaround wrt. ACK frames, the PAWS discard
		 * extra check below makes sure this can only happen
		 * for pure ACK frames.  -DaveM
		 *
		 * Not only, also it occurs for expired timestamps.
		 */

		if ((s32)(tp->rx_opt.rcv_tsval - tp->rx_opt.ts_recent) >= 0 ||
		   get_seconds() >= tp->rx_opt.ts_recent_stamp + TCP_PAWS_24DAYS)
			tcp_store_ts_recent(tp);
	}
}

/* Sorry, PAWS as specified is broken wrt. pure-ACKs -DaveM
 *
 * It is not fatal. If this ACK does _not_ change critical state (seqs, window)
 * it can pass through stack. So, the following predicate verifies that
 * this segment is not used for anything but congestion avoidance or
 * fast retransmit. Moreover, we even are able to eliminate most of such
 * second order effects, if we apply some small "replay" window (~RTO)
 * to timestamp space.
 *
 * All these measures still do not guarantee that we reject wrapped ACKs
 * on networks with high bandwidth, when sequence space is recycled fastly,
 * but it guarantees that such events will be very rare and do not affect
 * connection seriously. This doesn't look nice, but alas, PAWS is really
 * buggy extension.
 *
 * [ Later note. Even worse! It is buggy for segments _with_ data. RFC
 * states that events when retransmit arrives after original data are rare.
 * It is a blatant lie. VJ forgot about fast retransmit! 8)8) It is
 * the biggest problem on large power networks even with minor reordering.
 * OK, let's give it small replay window. If peer clock is even 1hz, it is safe
 * up to bandwidth of 18Gigabit/sec. 8) ]
 */

static int tcp_disordered_ack(const struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcphdr *th = tcp_hdr(skb);
	u32 seq = TCP_SKB_CB(skb)->seq;
	u32 ack = TCP_SKB_CB(skb)->ack_seq;

	return (/* 1. Pure ACK with correct sequence number. */
		(th->ack && seq == TCP_SKB_CB(skb)->end_seq && seq == tp->rcv_nxt) &&

		/* 2. ... and duplicate ACK. */
		ack == tp->snd_una &&

		/* 3. ... and does not update window. */
		!tcp_may_update_window(tp, ack, seq, ntohs(th->window) << tp->rx_opt.snd_wscale) &&

		/* 4. ... and sits in replay window. */
		(s32)(tp->rx_opt.ts_recent - tp->rx_opt.rcv_tsval) <= (inet_csk(sk)->icsk_rto * 1024) / HZ);
}

static inline int tcp_paws_discard(const struct sock *sk, const struct sk_buff *skb)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	return ((s32)(tp->rx_opt.ts_recent - tp->rx_opt.rcv_tsval) > TCP_PAWS_WINDOW &&
		get_seconds() < tp->rx_opt.ts_recent_stamp + TCP_PAWS_24DAYS &&
		!tcp_disordered_ack(sk, skb));
}

/* Check segment sequence number for validity.
 *
 * Segment controls are considered valid, if the segment
 * fits to the window after truncation to the window. Acceptability
 * of data (and SYN, FIN, of course) is checked separately.
 * See tcp_data_queue(), for example.
 *
 * Also, controls (RST is main one) are accepted using RCV.WUP instead
 * of RCV.NXT. Peer still did not advance his SND.UNA when we
 * delayed ACK, so that hisSND.UNA<=ourRCV.WUP.
 * (borrowed from freebsd)
 */

static inline int tcp_sequence(struct tcp_sock *tp, u32 seq, u32 end_seq)
{
	return	!before(end_seq, tp->rcv_wup) && !after(seq, tp->rcv_nxt + tcp_receive_window(tp));
}

/* When we get a reset we do this. */
static void tcp_reset(struct sock *sk)
{
	/* We want the right error as BSD sees it (and indeed as we do). */
	switch (sk->sk_state) {
		case TCP_SYN_SENT:
			sk->sk_err = ECONNREFUSED;
			break;
		case TCP_CLOSE_WAIT:
			sk->sk_err = EPIPE;
			break;
		case TCP_CLOSE:
			return;
		default:
			sk->sk_err = ECONNRESET;
	}

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_error_report(sk);

	tcp_done(sk);
}

/*
 * 	Process the FIN bit. This now behaves as it is supposed to work
 *	and the FIN takes effect when it is validly part of sequence
 *	space. Not before when we get holes.
 *
 *	If we are ESTABLISHED, a received fin moves us to CLOSE-WAIT
 *	(and thence onto LAST-ACK and finally, CLOSE, we never enter
 *	TIME-WAIT)
 *
 *	If we are in FINWAIT-1, a received FIN indicates simultaneous
 *	close and we go into CLOSING (and later onto TIME-WAIT)
 *
 *	If we are in FINWAIT-2, a received FIN moves us to TIME-WAIT.
 */
static void tcp_fin(struct sk_buff *skb, struct sock *sk, struct tcphdr *th)
{
	struct tcp_sock *tp = tcp_sk(sk);

	inet_csk_schedule_ack(sk);

	sk->sk_shutdown |= RCV_SHUTDOWN;
	sock_set_flag(sk, SOCK_DONE);

	switch (sk->sk_state) {
		case TCP_SYN_RECV:
		case TCP_ESTABLISHED:
			/* Move to CLOSE_WAIT */
			tcp_set_state(sk, TCP_CLOSE_WAIT);
			inet_csk(sk)->icsk_ack.pingpong = 1;
			break;

		case TCP_CLOSE_WAIT:
		case TCP_CLOSING:
			/* Received a retransmission of the FIN, do
			 * nothing.
			 */
			break;
		case TCP_LAST_ACK:
			/* RFC793: Remain in the LAST-ACK state. */
			break;

		case TCP_FIN_WAIT1:
			/* This case occurs when a simultaneous close
			 * happens, we must ack the received FIN and
			 * enter the CLOSING state.
			 */
			tcp_send_ack(sk);
			tcp_set_state(sk, TCP_CLOSING);
			break;
		case TCP_FIN_WAIT2:
			/* Received a FIN -- send ACK and enter TIME_WAIT. */
			tcp_send_ack(sk);
			tcp_time_wait(sk, TCP_TIME_WAIT, 0);
			break;
		default:
			/* Only TCP_LISTEN and TCP_CLOSE are left, in these
			 * cases we should never reach this piece of code.
			 */
			printk(KERN_ERR "%s: Impossible, sk->sk_state=%d\n",
			       __FUNCTION__, sk->sk_state);
			break;
	}

	/* It _is_ possible, that we have something out-of-order _after_ FIN.
	 * Probably, we should reset in this case. For now drop them.
	 */
	__skb_queue_purge(&tp->out_of_order_queue);
	if (tcp_is_sack(tp))
		tcp_sack_reset(&tp->rx_opt);
	sk_stream_mem_reclaim(sk);

	if (!sock_flag(sk, SOCK_DEAD)) {
		sk->sk_state_change(sk);

		/* Do not send POLL_HUP for half duplex close. */
		if (sk->sk_shutdown == SHUTDOWN_MASK ||
		    sk->sk_state == TCP_CLOSE)
			sk_wake_async(sk, 1, POLL_HUP);
		else
			sk_wake_async(sk, 1, POLL_IN);
	}
}

static inline int tcp_sack_extend(struct tcp_sack_block *sp, u32 seq, u32 end_seq)
{
	if (!after(seq, sp->end_seq) && !after(sp->start_seq, end_seq)) {
		if (before(seq, sp->start_seq))
			sp->start_seq = seq;
		if (after(end_seq, sp->end_seq))
			sp->end_seq = end_seq;
		return 1;
	}
	return 0;
}

static void tcp_dsack_set(struct tcp_sock *tp, u32 seq, u32 end_seq)
{
	if (tcp_is_sack(tp) && sysctl_tcp_dsack) {
		if (before(seq, tp->rcv_nxt))
			NET_INC_STATS_BH(LINUX_MIB_TCPDSACKOLDSENT);
		else
			NET_INC_STATS_BH(LINUX_MIB_TCPDSACKOFOSENT);

		tp->rx_opt.dsack = 1;
		tp->duplicate_sack[0].start_seq = seq;
		tp->duplicate_sack[0].end_seq = end_seq;
		tp->rx_opt.eff_sacks = min(tp->rx_opt.num_sacks + 1, 4 - tp->rx_opt.tstamp_ok);
	}
}

static void tcp_dsack_extend(struct tcp_sock *tp, u32 seq, u32 end_seq)
{
	if (!tp->rx_opt.dsack)
		tcp_dsack_set(tp, seq, end_seq);
	else
		tcp_sack_extend(tp->duplicate_sack, seq, end_seq);
}

static void tcp_send_dupack(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq && before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) 
	{
		NET_INC_STATS_BH(LINUX_MIB_DELAYEDACKLOST);
		tcp_enter_quickack_mode(sk);

		if (tcp_is_sack(tp) && sysctl_tcp_dsack)
		{
			u32 end_seq = TCP_SKB_CB(skb)->end_seq;

			if (after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt))
				end_seq = tp->rcv_nxt;
			tcp_dsack_set(tp, TCP_SKB_CB(skb)->seq, end_seq);
		}
	}

	tcp_send_ack(sk);
}

/* These routines update the SACK block as out-of-order packets arrive or
 * in-order packets close up the sequence space.
 */
static void tcp_sack_maybe_coalesce(struct tcp_sock *tp)
{
	int this_sack;
	struct tcp_sack_block *sp = &tp->selective_acks[0];
	struct tcp_sack_block *swalk = sp+1;

	/* See if the recent change to the first SACK eats into
	 * or hits the sequence space of other SACK blocks, if so coalesce.
	 */
	for (this_sack = 1; this_sack < tp->rx_opt.num_sacks; ) {
		if (tcp_sack_extend(sp, swalk->start_seq, swalk->end_seq)) {
			int i;

			/* Zap SWALK, by moving every further SACK up by one slot.
			 * Decrease num_sacks.
			 */
			tp->rx_opt.num_sacks--;
			tp->rx_opt.eff_sacks = min(tp->rx_opt.num_sacks + tp->rx_opt.dsack, 4 - tp->rx_opt.tstamp_ok);
			for (i=this_sack; i < tp->rx_opt.num_sacks; i++)
				sp[i] = sp[i+1];
			continue;
		}
		this_sack++, swalk++;
	}
}

static inline void tcp_sack_swap(struct tcp_sack_block *sack1, struct tcp_sack_block *sack2)
{
	__u32 tmp;

	tmp = sack1->start_seq;
	sack1->start_seq = sack2->start_seq;
	sack2->start_seq = tmp;

	tmp = sack1->end_seq;
	sack1->end_seq = sack2->end_seq;
	sack2->end_seq = tmp;
}

static void tcp_sack_new_ofo_skb(struct sock *sk, u32 seq, u32 end_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_sack_block *sp = &tp->selective_acks[0];
	int cur_sacks = tp->rx_opt.num_sacks;
	int this_sack;

	if (!cur_sacks)
		goto new_sack;

	for (this_sack=0; this_sack<cur_sacks; this_sack++, sp++) {
		if (tcp_sack_extend(sp, seq, end_seq)) {
			/* Rotate this_sack to the first one. */
			for (; this_sack>0; this_sack--, sp--)
				tcp_sack_swap(sp, sp-1);
			if (cur_sacks > 1)
				tcp_sack_maybe_coalesce(tp);
			return;
		}
	}

	/* Could not find an adjacent existing SACK, build a new one,
	 * put it at the front, and shift everyone else down.  We
	 * always know there is at least one SACK present already here.
	 *
	 * If the sack array is full, forget about the last one.
	 */
	if (this_sack >= 4) {
		this_sack--;
		tp->rx_opt.num_sacks--;
		sp--;
	}
	for (; this_sack > 0; this_sack--, sp--)
		*sp = *(sp-1);

new_sack:
	/* Build the new head SACK, and we're done. */
	sp->start_seq = seq;
	sp->end_seq = end_seq;
	tp->rx_opt.num_sacks++;
	tp->rx_opt.eff_sacks = min(tp->rx_opt.num_sacks + tp->rx_opt.dsack, 4 - tp->rx_opt.tstamp_ok);
}

/* RCV.NXT advances, some SACKs should be eaten. */
static void tcp_sack_remove(struct tcp_sock *tp)
{
	struct tcp_sack_block *sp = &tp->selective_acks[0];
	int num_sacks = tp->rx_opt.num_sacks;
	int this_sack;

	/* Empty ofo queue, hence, all the SACKs are eaten. Clear. */
	if (skb_queue_empty(&tp->out_of_order_queue)) 
	{
		tp->rx_opt.num_sacks = 0;
		tp->rx_opt.eff_sacks = tp->rx_opt.dsack;
		return;
	}

	for (this_sack = 0; this_sack < num_sacks; ) 
	{
		/* Check if the start of the sack is covered by RCV.NXT. */
		if (!before(tp->rcv_nxt, sp->start_seq)) 
		{
			int i;

			/* RCV.NXT must cover all the block! */
			BUG_TRAP(!before(tp->rcv_nxt, sp->end_seq));

			/* Zap this SACK, by moving forward any other SACKS. */
			for (i=this_sack+1; i < num_sacks; i++)
				tp->selective_acks[i-1] = tp->selective_acks[i];
			num_sacks--;
			continue;
		}
		this_sack++;
		sp++;
	}
	if (num_sacks != tp->rx_opt.num_sacks) {
		tp->rx_opt.num_sacks = num_sacks;
		tp->rx_opt.eff_sacks = min(tp->rx_opt.num_sacks + tp->rx_opt.dsack, 4 - tp->rx_opt.tstamp_ok);
	}
}

/* This one checks to see if we can put data from the
 * out_of_order queue into the receive_queue.
 */
static void tcp_ofo_queue(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 dsack_high = tp->rcv_nxt;
	struct sk_buff *skb;

	 //±éÀúout_of_order¶ÓÁÐ  
	while ((skb = skb_peek(&tp->out_of_order_queue)) != NULL) 
	{
		if (after(TCP_SKB_CB(skb)->seq, tp->rcv_nxt))
			break;

		if (before(TCP_SKB_CB(skb)->seq, dsack_high))
		{
			__u32 dsack = dsack_high;
			if (before(TCP_SKB_CB(skb)->end_seq, dsack_high))
				dsack_high = TCP_SKB_CB(skb)->end_seq;
			tcp_dsack_extend(tp, TCP_SKB_CB(skb)->seq, dsack);
		}

		if (!after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt)) 
		{
			SOCK_DEBUG(sk, "ofo packet was already received \n");
			__skb_unlink(skb, &tp->out_of_order_queue);
			__kfree_skb(skb);
			continue;
		}
		SOCK_DEBUG(sk, "ofo requeuing : rcv_next %X seq %X - %X\n", tp->rcv_nxt, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq);
		//ÈôÕâ¸ö±¨ÎÄ¿ÉÒÔ°´seq²åÈëÓÐÐòµÄreceive¶ÓÁÐÖÐ£¬Ôò½«ÆäÒÆ³öout_of_order¶ÓÁÐ 
		__skb_unlink(skb, &tp->out_of_order_queue);
		 //²åÈëreceive¶ÓÁÐ  
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		 //¸üÐÂsocketÉÏ´ý½ÓÊÕµÄÏÂÒ»¸öÓÐÐòseq 
		tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		if (tcp_hdr(skb)->fin)
			tcp_fin(skb, sk, tcp_hdr(skb));
	}
}

static int tcp_prune_queue(struct sock *sk);

static void tcp_data_queue(struct sock *sk, struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	struct tcp_sock *tp = tcp_sk(sk);
	int eaten = -1;

	if (TCP_SKB_CB(skb)->seq == TCP_SKB_CB(skb)->end_seq)
		goto drop;

	__skb_pull(skb, th->doff*4);

	TCP_ECN_accept_cwr(tp, skb);

	if (tp->rx_opt.dsack) 
	{
		tp->rx_opt.dsack = 0;
		tp->rx_opt.eff_sacks = min_t(unsigned int, tp->rx_opt.num_sacks,
						    4 - tp->rx_opt.tstamp_ok);
	}

	/*  Queue data for delivery to the user.
	 *  Packets in sequence go to the receive queue.
	 *  Out of sequence packets to the out_of_order_queue.
	 */
	//Èç¹ûÕâ¸ö±¨ÎÄÊÇ´ý½ÓÊÕµÄ±¨ÎÄ£¨¿´seq£©£¬ËüÓÐÁ½¸ö³öÂ·£º½øÈëreceive¶ÓÁÐ£¬Ö±½Ó¿½±´µ½ÓÃ»§ÄÚ´æÖÐ£¬
	if (TCP_SKB_CB(skb)->seq == tp->rcv_nxt) 
	{
		//»¬¶¯´°¿ÚÍâ
		if (tcp_receive_window(tp) == 0)
			goto out_of_window;

		/* Ok. In sequence. In window. */
		//Èç¹ûÓÐÒ»¸ö½ø³ÌÕýÔÚ¶ÁÈ¡socket£¬ÇÒÕý×¼±¸Òª¿½±´µÄÐòºÅ¾ÍÊÇµ±Ç°±¨ÎÄµÄseqÐòºÅ  
		// ÔÚÈíÖÐ¶ÏÉÏÏÂÎÄÖÐsock_owned_by_user(sk)¿ÉÄÜÎª1Âðå
		if (tp->ucopy.task == current && tp->copied_seq == tp->rcv_nxt && tp->ucopy.len && sock_owned_by_user(sk) && !tp->urg_data) 
		{
			int chunk = min_t(unsigned int, skb->len, tp->ucopy.len);

			__set_current_state(TASK_RUNNING);

			local_bh_enable();

			//Ö±½Ó½«±¨ÎÄÄÚÈÝ¿½±´µ½ÓÃ»§Ì¬ÄÚ´æÖÐ
			//
			if (!skb_copy_datagram_iovec(skb, 0, tp->ucopy.iov, chunk)) 
			{
				tp->ucopy.len -= chunk;
				tp->copied_seq += chunk;
				eaten = (chunk == skb->len && !th->fin);
				tcp_rcv_space_adjust(sk);
			}
			local_bh_disable();
		}

		if (eaten <= 0) 
		{
queue_and_out:
			if (eaten < 0 && (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf || !sk_stream_rmem_schedule(sk, skb)))
			{
				if (tcp_prune_queue(sk) < 0 || !sk_stream_rmem_schedule(sk, skb))
					goto drop;
			}
			sk_stream_set_owner_r(skb, sk);
			//Èç¹ûÃ»ÓÐÄÜ¹»Ö±½Ó¿½±´µ½ÓÃ»§ÄÚ´æÖÐ£¬ÄÇÃ´£¬²åÈëreceive¶ÓÁÐ°É
			__skb_queue_tail(&sk->sk_receive_queue, skb);
		}

		//¸üÐÂ´ý½ÓÊÕµÄÐòºÅ
		tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		if (skb->len)
			tcp_event_data_recv(sk, skb);
		if (th->fin)
			tcp_fin(skb, sk, th);

		//ÕâÊ±»á¼ì²éout_of_order¶ÓÁÐ£¬ÈôËü²»Îª¿Õ£¬ÐèÒª´¦ÀíËü
		if (!skb_queue_empty(&tp->out_of_order_queue)) 
		{
			tcp_ofo_queue(sk);

			/* RFC2581. 4.2. SHOULD send immediate ACK, when
			 * gap in queue is filled.
			 */
			if (skb_queue_empty(&tp->out_of_order_queue))
				inet_csk(sk)->icsk_ack.pingpong = 0;
		}

		if (tp->rx_opt.num_sacks)
			tcp_sack_remove(tp);

		tcp_fast_path_check(sk);

		if (eaten > 0)
			__kfree_skb(skb);
		else if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_data_ready(sk, 0);
		return;
	}

	if (!after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt)) 
	{
		/* A retransmit, 2nd most common case.  Force an immediate ack. */
		NET_INC_STATS_BH(LINUX_MIB_DELAYEDACKLOST);
		tcp_dsack_set(tp, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq);

out_of_window:
		tcp_enter_quickack_mode(sk);
		inet_csk_schedule_ack(sk);
drop:
		__kfree_skb(skb);
		return;
	}

	/* Out of window. F.e. zero window probe. */
	if (!before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt + tcp_receive_window(tp)))
		goto out_of_window;

	tcp_enter_quickack_mode(sk);

	if (before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {
		/* Partial packet, seq < rcv_next < end_seq */
		SOCK_DEBUG(sk, "partial packet: rcv_next %X seq %X - %X\n",
			   tp->rcv_nxt, TCP_SKB_CB(skb)->seq,
			   TCP_SKB_CB(skb)->end_seq);

		tcp_dsack_set(tp, TCP_SKB_CB(skb)->seq, tp->rcv_nxt);

		/* If window is closed, drop tail of packet. But after
		 * remembering D-SACK for its head made in previous line.
		 */
		if (!tcp_receive_window(tp))
			goto out_of_window;
		goto queue_and_out;
	}

	TCP_ECN_check_ce(tp, skb);

	if (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf ||
	    !sk_stream_rmem_schedule(sk, skb)) {
		if (tcp_prune_queue(sk) < 0 ||
		    !sk_stream_rmem_schedule(sk, skb))
			goto drop;
	}

	/* Disable header prediction. */
	tp->pred_flags = 0;
	inet_csk_schedule_ack(sk);

	SOCK_DEBUG(sk, "out of order segment: rcv_next %X seq %X - %X\n",
		   tp->rcv_nxt, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq);

	sk_stream_set_owner_r(skb, sk);
	//Õâ¸ö°üÊÇÎÞÐòµÄ£¬ÓÖÔÚ½ÓÊÕ»¬¶¯´°¿ÚÄÚ£¬°Ñ±¨ÎÄ²åÈëµ½out_of_order¶ÓÁÐ°É
	if (!skb_peek(&tp->out_of_order_queue)) 
	{
		/* Initial out of order segment, build 1 SACK. */
		if (tcp_is_sack(tp))
		{
			tp->rx_opt.num_sacks = 1;
			tp->rx_opt.dsack     = 0;
			tp->rx_opt.eff_sacks = 1;
			tp->selective_acks[0].start_seq = TCP_SKB_CB(skb)->seq;
			tp->selective_acks[0].end_seq = TCP_SKB_CB(skb)->end_seq;
		}
		__skb_queue_head(&tp->out_of_order_queue,skb);
	} else {
		struct sk_buff *skb1 = tp->out_of_order_queue.prev;
		u32 seq = TCP_SKB_CB(skb)->seq;
		u32 end_seq = TCP_SKB_CB(skb)->end_seq;

		if (seq == TCP_SKB_CB(skb1)->end_seq) {
			__skb_append(skb1, skb, &tp->out_of_order_queue);

			if (!tp->rx_opt.num_sacks ||
			    tp->selective_acks[0].end_seq != seq)
				goto add_sack;

			/* Common case: data arrive in order after hole. */
			tp->selective_acks[0].end_seq = end_seq;
			return;
		}

		/* Find place to insert this segment. */
		do {
			if (!after(TCP_SKB_CB(skb1)->seq, seq))
				break;
		} while ((skb1 = skb1->prev) !=
			 (struct sk_buff*)&tp->out_of_order_queue);

		/* Do skb overlap to previous one? */
		if (skb1 != (struct sk_buff*)&tp->out_of_order_queue &&
		    before(seq, TCP_SKB_CB(skb1)->end_seq)) {
			if (!after(end_seq, TCP_SKB_CB(skb1)->end_seq)) {
				/* All the bits are present. Drop. */
				__kfree_skb(skb);
				tcp_dsack_set(tp, seq, end_seq);
				goto add_sack;
			}
			if (after(seq, TCP_SKB_CB(skb1)->seq)) {
				/* Partial overlap. */
				tcp_dsack_set(tp, seq, TCP_SKB_CB(skb1)->end_seq);
			} else {
				skb1 = skb1->prev;
			}
		}
		__skb_insert(skb, skb1, skb1->next, &tp->out_of_order_queue);

		/* And clean segments covered by new one as whole. */
		while ((skb1 = skb->next) !=
		       (struct sk_buff*)&tp->out_of_order_queue &&
		       after(end_seq, TCP_SKB_CB(skb1)->seq)) {
		       if (before(end_seq, TCP_SKB_CB(skb1)->end_seq)) {
			       tcp_dsack_extend(tp, TCP_SKB_CB(skb1)->seq, end_seq);
			       break;
		       }
		       __skb_unlink(skb1, &tp->out_of_order_queue);
		       tcp_dsack_extend(tp, TCP_SKB_CB(skb1)->seq, TCP_SKB_CB(skb1)->end_seq);
		       __kfree_skb(skb1);
		}

add_sack:
		if (tcp_is_sack(tp))
			tcp_sack_new_ofo_skb(sk, seq, end_seq);
	}
}

/* Collapse contiguous sequence of skbs head..tail with
 * sequence numbers start..end.
 * Segments with FIN/SYN are not collapsed (only because this
 * simplifies code)
 */
static void
tcp_collapse(struct sock *sk, struct sk_buff_head *list,
	     struct sk_buff *head, struct sk_buff *tail,
	     u32 start, u32 end)
{
	struct sk_buff *skb;

	/* First, check that queue is collapsible and find
	 * the point where collapsing can be useful. */
	for (skb = head; skb != tail; ) {
		/* No new bits? It is possible on ofo queue. */
		if (!before(start, TCP_SKB_CB(skb)->end_seq)) {
			struct sk_buff *next = skb->next;
			__skb_unlink(skb, list);
			__kfree_skb(skb);
			NET_INC_STATS_BH(LINUX_MIB_TCPRCVCOLLAPSED);
			skb = next;
			continue;
		}

		/* The first skb to collapse is:
		 * - not SYN/FIN and
		 * - bloated or contains data before "start" or
		 *   overlaps to the next one.
		 */
		if (!tcp_hdr(skb)->syn && !tcp_hdr(skb)->fin &&
		    (tcp_win_from_space(skb->truesize) > skb->len ||
		     before(TCP_SKB_CB(skb)->seq, start) ||
		     (skb->next != tail &&
		      TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb->next)->seq)))
			break;

		/* Decided to skip this, advance start seq. */
		start = TCP_SKB_CB(skb)->end_seq;
		skb = skb->next;
	}
	if (skb == tail || tcp_hdr(skb)->syn || tcp_hdr(skb)->fin)
		return;

	while (before(start, end)) {
		struct sk_buff *nskb;
		unsigned int header = skb_headroom(skb);
		int copy = SKB_MAX_ORDER(header, 0);

		/* Too big header? This can happen with IPv6. */
		if (copy < 0)
			return;
		if (end-start < copy)
			copy = end-start;
		nskb = alloc_skb(copy+header, GFP_ATOMIC);
		if (!nskb)
			return;

		skb_set_mac_header(nskb, skb_mac_header(skb) - skb->head);
		skb_set_network_header(nskb, (skb_network_header(skb) -
					      skb->head));
		skb_set_transport_header(nskb, (skb_transport_header(skb) -
						skb->head));
		skb_reserve(nskb, header);
		memcpy(nskb->head, skb->head, header);
		memcpy(nskb->cb, skb->cb, sizeof(skb->cb));
		TCP_SKB_CB(nskb)->seq = TCP_SKB_CB(nskb)->end_seq = start;
		__skb_insert(nskb, skb->prev, skb, list);
		sk_stream_set_owner_r(nskb, sk);

		/* Copy data, releasing collapsed skbs. */
		while (copy > 0) {
			int offset = start - TCP_SKB_CB(skb)->seq;
			int size = TCP_SKB_CB(skb)->end_seq - start;

			BUG_ON(offset < 0);
			if (size > 0) {
				size = min(copy, size);
				if (skb_copy_bits(skb, offset, skb_put(nskb, size), size))
					BUG();
				TCP_SKB_CB(nskb)->end_seq += size;
				copy -= size;
				start += size;
			}
			if (!before(start, TCP_SKB_CB(skb)->end_seq)) {
				struct sk_buff *next = skb->next;
				__skb_unlink(skb, list);
				__kfree_skb(skb);
				NET_INC_STATS_BH(LINUX_MIB_TCPRCVCOLLAPSED);
				skb = next;
				if (skb == tail ||
				    tcp_hdr(skb)->syn ||
				    tcp_hdr(skb)->fin)
					return;
			}
		}
	}
}

/* Collapse ofo queue. Algorithm: select contiguous sequence of skbs
 * and tcp_collapse() them until all the queue is collapsed.
 */
static void tcp_collapse_ofo_queue(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = skb_peek(&tp->out_of_order_queue);
	struct sk_buff *head;
	u32 start, end;

	if (skb == NULL)
		return;

	start = TCP_SKB_CB(skb)->seq;
	end = TCP_SKB_CB(skb)->end_seq;
	head = skb;

	for (;;) {
		skb = skb->next;

		/* Segment is terminated when we see gap or when
		 * we are at the end of all the queue. */
		if (skb == (struct sk_buff *)&tp->out_of_order_queue ||
		    after(TCP_SKB_CB(skb)->seq, end) ||
		    before(TCP_SKB_CB(skb)->end_seq, start)) {
			tcp_collapse(sk, &tp->out_of_order_queue,
				     head, skb, start, end);
			head = skb;
			if (skb == (struct sk_buff *)&tp->out_of_order_queue)
				break;
			/* Start new segment */
			start = TCP_SKB_CB(skb)->seq;
			end = TCP_SKB_CB(skb)->end_seq;
		} else {
			if (before(TCP_SKB_CB(skb)->seq, start))
				start = TCP_SKB_CB(skb)->seq;
			if (after(TCP_SKB_CB(skb)->end_seq, end))
				end = TCP_SKB_CB(skb)->end_seq;
		}
	}
}

/* Reduce allocated memory if we can, trying to get
 * the socket within its memory limits again.
 *
 * Return less than zero if we should start dropping frames
 * until the socket owning process reads some of the data
 * to stabilize the situation.
 */
static int tcp_prune_queue(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	SOCK_DEBUG(sk, "prune_queue: c=%x\n", tp->copied_seq);

	NET_INC_STATS_BH(LINUX_MIB_PRUNECALLED);

	if (atomic_read(&sk->sk_rmem_alloc) >= sk->sk_rcvbuf)
		tcp_clamp_window(sk);
	else if (tcp_memory_pressure)
		tp->rcv_ssthresh = min(tp->rcv_ssthresh, 4U * tp->advmss);

	tcp_collapse_ofo_queue(sk);
	tcp_collapse(sk, &sk->sk_receive_queue,
		     sk->sk_receive_queue.next,
		     (struct sk_buff*)&sk->sk_receive_queue,
		     tp->copied_seq, tp->rcv_nxt);
	sk_stream_mem_reclaim(sk);

	if (atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf)
		return 0;

	/* Collapsing did not help, destructive actions follow.
	 * This must not ever occur. */

	/* First, purge the out_of_order queue. */
	if (!skb_queue_empty(&tp->out_of_order_queue)) {
		NET_INC_STATS_BH(LINUX_MIB_OFOPRUNED);
		__skb_queue_purge(&tp->out_of_order_queue);

		/* Reset SACK state.  A conforming SACK implementation will
		 * do the same at a timeout based retransmit.  When a connection
		 * is in a sad state like this, we care only about integrity
		 * of the connection not performance.
		 */
		if (tcp_is_sack(tp))
			tcp_sack_reset(&tp->rx_opt);
		sk_stream_mem_reclaim(sk);
	}

	if (atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf)
		return 0;

	/* If we are really being abused, tell the caller to silently
	 * drop receive data on the floor.  It will get retransmitted
	 * and hopefully then we'll have sufficient space.
	 */
	NET_INC_STATS_BH(LINUX_MIB_RCVPRUNED);

	/* Massive buffer overcommit. */
	tp->pred_flags = 0;
	return -1;
}


/* RFC2861, slow part. Adjust cwnd, after it was not full during one rto.
 * As additional protections, we do not touch cwnd in retransmission phases,
 * and if application hit its sndbuf limit recently.
 */
void tcp_cwnd_application_limited(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Open &&
	    sk->sk_socket && !test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		/* Limited by application or receiver window. */
		u32 init_win = tcp_init_cwnd(tp, __sk_dst_get(sk));
		u32 win_used = max(tp->snd_cwnd_used, init_win);
		if (win_used < tp->snd_cwnd) {
			tp->snd_ssthresh = tcp_current_ssthresh(sk);
			tp->snd_cwnd = (tp->snd_cwnd + win_used) >> 1;
		}
		tp->snd_cwnd_used = 0;
	}
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

static int tcp_should_expand_sndbuf(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* If the user specified a specific send buffer setting, do
	 * not modify it.
	 */
	if (sk->sk_userlocks & SOCK_SNDBUF_LOCK)
		return 0;

	/* If we are under global TCP memory pressure, do not expand.  */
	if (tcp_memory_pressure)
		return 0;

	/* If we are under soft global TCP memory pressure, do not expand.  */
	if (atomic_read(&tcp_memory_allocated) >= sysctl_tcp_mem[0])
		return 0;

	/* If we filled the congestion window, do not expand.  */
	if (tp->packets_out >= tp->snd_cwnd)
		return 0;

	return 1;
}

/* When incoming ACK allowed to free some skb from write_queue,
 * we remember this event in flag SOCK_QUEUE_SHRUNK and wake up socket
 * on the exit from tcp input handler.
 *
 * PROBLEM: sndbuf expansion does not work well with largesend.
 */
static void tcp_new_space(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tcp_should_expand_sndbuf(sk)) {
		int sndmem = max_t(u32, tp->rx_opt.mss_clamp, tp->mss_cache) +
			MAX_TCP_HEADER + 16 + sizeof(struct sk_buff),
		    demanded = max_t(unsigned int, tp->snd_cwnd,
						   tp->reordering + 1);
		sndmem *= 2*demanded;
		if (sndmem > sk->sk_sndbuf)
			sk->sk_sndbuf = min(sndmem, sysctl_tcp_wmem[2]);
		tp->snd_cwnd_stamp = tcp_time_stamp;
	}

	sk->sk_write_space(sk);
}

static void tcp_check_space(struct sock *sk)
{
	if (sock_flag(sk, SOCK_QUEUE_SHRUNK)) {
		sock_reset_flag(sk, SOCK_QUEUE_SHRUNK);
		if (sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &sk->sk_socket->flags))
			tcp_new_space(sk);
	}
}

static inline void tcp_data_snd_check(struct sock *sk)
{
	tcp_push_pending_frames(sk);
	tcp_check_space(sk);
}

/*
 * Check if sending an ack is needed.
 */
static void __tcp_ack_snd_check(struct sock *sk, int ofo_possible)
{
	struct tcp_sock *tp = tcp_sk(sk);

	    /* More than one full frame received... */
	if (((tp->rcv_nxt - tp->rcv_wup) > inet_csk(sk)->icsk_ack.rcv_mss  //Èç¹û½ÓÊÕµ½ÁË´óÓÚÒ»¸öµÄ±¨ÎÄ£¬ÄÇÃ´¾Í·¢ËÍack£¬Ò»ÏÂ×ÓÈ·ÈÏÁ½¸ö±¨ÎÄ
	     /* ... and right edge of window advances far enough.
	      * (tcp_recvmsg() will send ACK otherwise). Or...
	      */
	     && __tcp_select_window(sk) >= tp->rcv_wnd) ||					//ÐèÒªµ÷Õû´°¿Ú£¬×î´ó»¯ÍÌÍÂÁ¿
	    /* We ACK each frame or... */
	    tcp_in_quickack_mode(sk) ||
	    /* We have out of order data. */
	    (ofo_possible && skb_peek(&tp->out_of_order_queue)))  			//ÊÕµ½ÂÒÐòµÄ°ü
	{
		/* Then ack it now */
		tcp_send_ack(sk);
	}
	else 
	{
		/* Else, send delayed ack. */
		tcp_send_delayed_ack(sk);
	}
}

static inline void tcp_ack_snd_check(struct sock *sk)
{
	if (!inet_csk_ack_scheduled(sk)) {
		/* We sent a data segment already. */
		return;
	}
	__tcp_ack_snd_check(sk, 1);
}

/*
 *	This routine is only called when we have urgent data
 *	signaled. Its the 'slow' part of tcp_urg. It could be
 *	moved inline now as tcp_urg is only called from one
 *	place. We handle URGent data wrong. We have to - as
 *	BSD still doesn't use the correction from RFC961.
 *	For 1003.1g we should support a new option TCP_STDURG to permit
 *	either form (or just set the sysctl tcp_stdurg).
 */

static void tcp_check_urg(struct sock * sk, struct tcphdr * th)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 ptr = ntohs(th->urg_ptr);

	if (ptr && !sysctl_tcp_stdurg)
		ptr--;
	ptr += ntohl(th->seq);

	/* Ignore urgent data that we've already seen and read. */
	if (after(tp->copied_seq, ptr))
		return;

	/* Do not replay urg ptr.
	 *
	 * NOTE: interesting situation not covered by specs.
	 * Misbehaving sender may send urg ptr, pointing to segment,
	 * which we already have in ofo queue. We are not able to fetch
	 * such data and will stay in TCP_URG_NOTYET until will be eaten
	 * by recvmsg(). Seems, we are not obliged to handle such wicked
	 * situations. But it is worth to think about possibility of some
	 * DoSes using some hypothetical application level deadlock.
	 */
	if (before(ptr, tp->rcv_nxt))
		return;

	/* Do we already have a newer (or duplicate) urgent pointer? */
	if (tp->urg_data && !after(ptr, tp->urg_seq))
		return;

	/* Tell the world about our new urgent pointer. */
	sk_send_sigurg(sk);

	/* We may be adding urgent data when the last byte read was
	 * urgent. To do this requires some care. We cannot just ignore
	 * tp->copied_seq since we would read the last urgent byte again
	 * as data, nor can we alter copied_seq until this data arrives
	 * or we break the semantics of SIOCATMARK (and thus sockatmark())
	 *
	 * NOTE. Double Dutch. Rendering to plain English: author of comment
	 * above did something sort of 	send("A", MSG_OOB); send("B", MSG_OOB);
	 * and expect that both A and B disappear from stream. This is _wrong_.
	 * Though this happens in BSD with high probability, this is occasional.
	 * Any application relying on this is buggy. Note also, that fix "works"
	 * only in this artificial test. Insert some normal data between A and B and we will
	 * decline of BSD again. Verdict: it is better to remove to trap
	 * buggy users.
	 */
	if (tp->urg_seq == tp->copied_seq && tp->urg_data &&
	    !sock_flag(sk, SOCK_URGINLINE) &&
	    tp->copied_seq != tp->rcv_nxt) {
		struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);
		tp->copied_seq++;
		if (skb && !before(tp->copied_seq, TCP_SKB_CB(skb)->end_seq)) {
			__skb_unlink(skb, &sk->sk_receive_queue);
			__kfree_skb(skb);
		}
	}

	tp->urg_data   = TCP_URG_NOTYET;
	tp->urg_seq    = ptr;

	/* Disable header prediction. */
	tp->pred_flags = 0;
}

/* This is the 'fast' part of urgent handling. */
static void tcp_urg(struct sock *sk, struct sk_buff *skb, struct tcphdr *th)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Check if we get a new urgent pointer - normally not. */
	if (th->urg)
		tcp_check_urg(sk,th);

	/* Do we wait for any urgent data? - normally not... */
	if (tp->urg_data == TCP_URG_NOTYET) {
		u32 ptr = tp->urg_seq - ntohl(th->seq) + (th->doff * 4) -
			  th->syn;

		/* Is the urgent pointer pointing into this packet? */
		if (ptr < skb->len) {
			u8 tmp;
			if (skb_copy_bits(skb, ptr, &tmp, 1))
				BUG();
			tp->urg_data = TCP_URG_VALID | tmp;
			if (!sock_flag(sk, SOCK_DEAD))
				sk->sk_data_ready(sk, 0);
		}
	}
}

static int tcp_copy_to_iovec(struct sock *sk, struct sk_buff *skb, int hlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int chunk = skb->len - hlen;
	int err;

	local_bh_enable();
	if (skb_csum_unnecessary(skb))
		err = skb_copy_datagram_iovec(skb, hlen, tp->ucopy.iov, chunk);
	else
		err = skb_copy_and_csum_datagram_iovec(skb, hlen, tp->ucopy.iov);

	if (!err)
	{
		tp->ucopy.len -= chunk;
		tp->copied_seq += chunk;
		tcp_rcv_space_adjust(sk);
	}

	local_bh_disable();
	return err;
}

static __sum16 __tcp_checksum_complete_user(struct sock *sk, struct sk_buff *skb)
{
	__sum16 result;

	if (sock_owned_by_user(sk))
	{
		local_bh_enable();
		result = __tcp_checksum_complete(skb);
		local_bh_disable();
	}
	else
	{
		result = __tcp_checksum_complete(skb);
	}
	return result;
}

static inline int tcp_checksum_complete_user(struct sock *sk, struct sk_buff *skb)
{
	return !skb_csum_unnecessary(skb) && __tcp_checksum_complete_user(sk, skb);
}

#ifdef CONFIG_NET_DMA
static int tcp_dma_try_early_copy(struct sock *sk, struct sk_buff *skb, int hlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int chunk = skb->len - hlen;
	int dma_cookie;
	int copied_early = 0;

	if (tp->ucopy.wakeup)
		return 0;

	if (!tp->ucopy.dma_chan && tp->ucopy.pinned_list)
		tp->ucopy.dma_chan = get_softnet_dma();

	if (tp->ucopy.dma_chan && skb_csum_unnecessary(skb)) {

		dma_cookie = dma_skb_copy_datagram_iovec(tp->ucopy.dma_chan,
			skb, hlen, tp->ucopy.iov, chunk, tp->ucopy.pinned_list);

		if (dma_cookie < 0)
			goto out;

		tp->ucopy.dma_cookie = dma_cookie;
		copied_early = 1;

		tp->ucopy.len -= chunk;
		tp->copied_seq += chunk;
		tcp_rcv_space_adjust(sk);

		if ((tp->ucopy.len == 0) ||
		    (tcp_flag_word(tcp_hdr(skb)) & TCP_FLAG_PSH) ||
		    (atomic_read(&sk->sk_rmem_alloc) > (sk->sk_rcvbuf >> 1))) {
			tp->ucopy.wakeup = 1;
			sk->sk_data_ready(sk, 0);
		}
	} else if (chunk > 0) {
		tp->ucopy.wakeup = 1;
		sk->sk_data_ready(sk, 0);
	}
out:
	return copied_early;
}
#endif /* CONFIG_NET_DMA */

/*
 *	TCP receive function for the ESTABLISHED state.
 *
 *	It is split into a fast path and a slow path. The fast path is
 * 	disabled when:
 *	- A zero window was announced from us - zero window probing
 *        is only handled properly in the slow path.
 *	- Out of order segments arrived.
 *	- Urgent data is expected.
 *	- There is no buffer space left
 *	- Unexpected TCP flags/window values/header lengths are received
 *	  (detected by checking the TCP header against pred_flags)
 *	- Data is sent in both directions. Fast path only supports pure senders
 *	  or pure receivers (this means either the sequence number or the ack
 *	  value must stay constant)
 *	- Unexpected TCP option.
 *
 *	When these conditions are not satisfied it drops into a standard
 *	receive procedure patterned after RFC793 to handle all cases.
 *	The first three cases are guaranteed by proper pred_flags setting,
 *	the rest is checked inline. Fast processing is turned on in
 *	tcp_data_queue when everything is OK.
 */
int tcp_rcv_established(struct sock *sk, struct sk_buff *skb, struct tcphdr *th, unsigned len)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/*
	 *	Header prediction.
	 *	The code loosely follows the one in the famous
	 *	"30 instruction TCP receive" Van Jacobson mail.
	 *
	 *	Van's trick is to deposit buffers into socket queue
	 *	on a device interrupt, to call tcp_recv function
	 *	on the receive process context and checksum and copy
	 *	the buffer to user space. smart...
	 *
	 *	Our current scheme is not silly either but we take the
	 *	extra cost of the net_bh soft interrupt processing...
	 *	We do checksum and copy also but from device to kernel.
	 */

	tp->rx_opt.saw_tstamp = 0;

	/*	pred_flags is 0xS?10 << 16 + snd_wnd
	 *	if header_prediction is to be made
	 *	'S' will always be tp->tcp_header_len >> 2
	 *	'?' will be 0 for the fast path, otherwise pred_flags is 0 to
	 *  turn it off	(when there are holes in the receive space for instance)
	 *	PSH flag is ignored.
	 */
	 
	//½øÈëfast pathµÄÌõ¼þ
	//1.ÔÚÅÅ³ýRESERVED×Ö¶ÎºÍPSH±êÖ¾Î»ºÍÍ·²¿Âú×ãpred_flagsÔ¤²â
	//2.Êý¾Ý°üÒÔÕýÈ·µÄË³Ðò£¨¸ÃÊý¾Ý°üµÄµÚÒ»¸öÐòºÅ¾ÍÊÇÏÂ¸öÒª½ÓÊÕµÄÐòºÅ£©
	if ((tcp_flag_word(th) & TCP_HP_BITS) == tp->pred_flags && TCP_SKB_CB(skb)->seq == tp->rcv_nxt) 
	{
		int tcp_header_len = tp->tcp_header_len;

		/* Timestamp header prediction: tcp_header_len
		 * is automatically equal to th->doff*4 due to pred_flags
		 * match.
		 */

		/* Check timestamp */
		if (tcp_header_len == sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED)
		{
			__be32 *ptr = (__be32 *)(th + 1);

			/* No? Slow path! */
			if (*ptr != htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) | (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP))
				goto slow_path;

			tp->rx_opt.saw_tstamp = 1;
			++ptr;
			tp->rx_opt.rcv_tsval = ntohl(*ptr);
			++ptr;
			tp->rx_opt.rcv_tsecr = ntohl(*ptr);

			/* If PAWS failed, check it more carefully in slow path */
			if ((s32)(tp->rx_opt.rcv_tsval - tp->rx_opt.ts_recent) < 0)
				goto slow_path;

			/* DO NOT update ts_recent here, if checksum fails
			 * and timestamp was corrupted part, it will result
			 * in a hung connection since we will drop all
			 * future packets due to the PAWS test.
			 */
		}

		if (len <= tcp_header_len)
		{
			/* Bulk data transfer: sender */
			///Èç¹û·¢ËÍÀ´µÄ½öÊÇÒ»¸öTCPÍ·µÄ»°£¨Ã»ÓÐÉÓ´øÊý¾Ý»òÕß½ÓÊÕ¶Ë¼ì²âµ½ÓÐÂÒÐòÊý¾ÝÕâÐ©Çé¿öÊ±¶¼»á·¢ËÍÒ»¸ö´¿´âµÄACK°ü£©
			if (len == tcp_header_len) 
			{
				/* Predicted packet is in window by definition.
				 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
				 * Hence, check seq<=rcv_wup reduces to:
				 */
				if (tcp_header_len == (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) && tp->rcv_nxt == tp->rcv_wup)
					tcp_store_ts_recent(tp);

				/* We know that such packets are checksummed on entry.*/
				tcp_ack(sk, skb, 0);
				__kfree_skb(skb);
				//¼ì²éÊÇ·ñÓÐÊý¾Ý´ý·¢ËÍ
				tcp_data_snd_check(sk);
				return 0;
			} 
			else 
			{ /* Header too small */
				TCP_INC_STATS_BH(TCP_MIB_INERRS);
				goto discard;
			}
		}
		else 
		{
			int eaten = 0;
			int copied_early = 0;

			// ´ËÊý¾Ý°ü¸ÕºÃÊÇÓÃ»§¿Õ¼äÏÂÒ»¸ö¶ÁÈ¡µÄÊý¾Ý£¬²¢ÇÒÓÃ»§¿Õ¼ä¿É´æ·ÅÏÂ¸ÃÊý¾Ý°ü*/  
			if (tp->copied_seq == tp->rcv_nxt && len - tcp_header_len <= tp->ucopy.len) 
			{
#ifdef CONFIG_NET_DMA
				if (tcp_dma_try_early_copy(sk, skb, tcp_header_len)) {
					copied_early = 1;
					eaten = 1;
				}
#endif
				//Èç¹û¸Ãº¯ÊýÔÚ½ø³ÌÉÏÏÂÎÄÖÐµ÷ÓÃ²¢ÇÒsock±»ÓÃ»§Õ¼ÓÃµÄ»°
				if (tp->ucopy.task == current && sock_owned_by_user(sk) && !copied_early) 
				{
					//½ø³ÌÓÐ¿ÉÄÜ±»ÉèÖÃÎªTASK_INTERRUPTIBLE 
					__set_current_state(TASK_RUNNING);
					// Ö±½ÓcopyÊý¾Ýµ½ÓÃ»§¿Õ¼ä
					if (!tcp_copy_to_iovec(sk, skb, tcp_header_len))
						eaten = 1;
				}
				if (eaten) 
				{
					/* Predicted packet is in window by definition.
					 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
					 * Hence, check seq<=rcv_wup reduces to:
					 */
					if (tcp_header_len == (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) && tp->rcv_nxt == tp->rcv_wup)
						tcp_store_ts_recent(tp);
					/* ¸üÐÂRCV RTT£¬Dynamic Right-SizingËã·¨*/
					tcp_rcv_rtt_measure_ts(sk, skb);

					__skb_pull(skb, tcp_header_len);
					tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
					NET_INC_STATS_BH(LINUX_MIB_TCPHPHITSTOUSER);
				}
				if (copied_early)
					tcp_cleanup_rbuf(sk, skb->len);
			}

			//Ã»ÓÐÖ±½Ó¶Áµ½ÓÃ»§¿Õ¼ä
			if (!eaten)
			{
				if (tcp_checksum_complete_user(sk, skb))
					goto csum_error;

				/* Predicted packet is in window by definition.
				 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
				 * Hence, check seq<=rcv_wup reduces to:
				 */
				if (tcp_header_len == (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) && tp->rcv_nxt == tp->rcv_wup)
					tcp_store_ts_recent(tp);

				tcp_rcv_rtt_measure_ts(sk, skb);

				if ((int)skb->truesize > sk->sk_forward_alloc)
					goto step5;

				NET_INC_STATS_BH(LINUX_MIB_TCPHPHITS);

				/* Bulk data transfer: receiver */
				__skb_pull(skb,tcp_header_len);
				/* ½øÈëreceive queue ÅÅ¶Ó£¬ÒÔ´ýtcp_recvmsg¶ÁÈ¡*/
				__skb_queue_tail(&sk->sk_receive_queue, skb);
				sk_stream_set_owner_r(skb, sk);
				tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
			}

			/* Êý¾Ý°ü½ÓÊÕºóÐø´¦Àí*/ 
			tcp_event_data_recv(sk, skb);

			//ACK ´¦Àí
			if (TCP_SKB_CB(skb)->ack_seq != tp->snd_una)
			{
				/* Well, only one small jumplet in fast path... */
				tcp_ack(sk, skb, FLAG_DATA);
				tcp_data_snd_check(sk);
				if (!inet_csk_ack_scheduled(sk))
					goto no_ack;
			}
			/* ACK·¢ËÍ´¦Àí*/  
			__tcp_ack_snd_check(sk, 0);
no_ack:
#ifdef CONFIG_NET_DMA
			if (copied_early)
				__skb_queue_tail(&sk->sk_async_wait_queue, skb);
			else
#endif
			/* eatenÎª1£¬±íÊ¾Êý¾ÝÖ±½Ócopyµ½ÁËÓÃ»§¿Õ¼ä£¬ÕâÊ±ÎÞÐèÌáÐÑÓÃ»§½ø³ÌÊý¾ÝµÄµ½´ï£¬·ñÔòÐèµ÷ÓÃsk_data_readyÀ´Í¨Öª£¬ÒòÎª´ËÊ±Êý¾Ýµ½´ïÁËreceive queue*/ 
			if (eaten)
				__kfree_skb(skb);
			else
				sk->sk_data_ready(sk, 0);
			return 0;
		}
	}

slow_path:
	if (len < (th->doff<<2) || tcp_checksum_complete_user(sk, skb))
		goto csum_error;

	/*
	 * RFC1323: H1. Apply PAWS check first.
	 */
	if (tcp_fast_parse_options(skb, th, tp) && tp->rx_opt.saw_tstamp && tcp_paws_discard(sk, skb)) 
	{
		if (!th->rst) 
		{
			NET_INC_STATS_BH(LINUX_MIB_PAWSESTABREJECTED);
			tcp_send_dupack(sk, skb);
			goto discard;
		}
		/* Resets are accepted even if PAWS failed.

		   ts_recent update must be made after we are sure
		   that the packet is in window.
		 */
	}

	/*
	 *	Standard slow path.
	 */

	if (!tcp_sequence(tp, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq)) 
	{
		/* RFC793, page 37: "In all states except SYN-SENT, all reset
		 * (RST) segments are validated by checking their SEQ-fields."
		 * And page 69: "If an incoming segment is not acceptable,
		 * an acknowledgment should be sent in reply (unless the RST bit
		 * is set, if so drop the segment and return)".
		 */
		if (!th->rst)
			tcp_send_dupack(sk, skb);
		goto discard;
	}

	if (th->rst) 
	{
		tcp_reset(sk);
		goto discard;
	}

	tcp_replace_ts_recent(tp, TCP_SKB_CB(skb)->seq);

	if (th->syn && !before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) 
	{
		TCP_INC_STATS_BH(TCP_MIB_INERRS);
		NET_INC_STATS_BH(LINUX_MIB_TCPABORTONSYN);
		tcp_reset(sk);
		return 1;
	}

step5:
	if (th->ack)
		tcp_ack(sk, skb, FLAG_SLOWPATH);

	tcp_rcv_rtt_measure_ts(sk, skb);

	/* Process urgent data. */
	tcp_urg(sk, skb, th);

	/* step 7: process the segment text */
	tcp_data_queue(sk, skb);

	tcp_data_snd_check(sk);
	tcp_ack_snd_check(sk);
	return 0;

csum_error:
	TCP_INC_STATS_BH(TCP_MIB_INERRS);

discard:
	__kfree_skb(skb);
	return 0;
}

static int tcp_rcv_synsent_state_process(struct sock *sk, struct sk_buff *skb, struct tcphdr *th, unsigned len)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int saved_clamp = tp->rx_opt.mss_clamp;

	tcp_parse_options(skb, &tp->rx_opt, 0);

	if (th->ack) 
	{
		/* rfc793:
		 * "If the state is SYN-SENT then
		 *    first check the ACK bit
		 *      If the ACK bit is set
		 *	  If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send
		 *        a reset (unless the RST bit is set, if so drop
		 *        the segment and return)"
		 *
		 *  We do not send data with SYN, so that RFC-correct
		 *  test reduces to:
		 */
		if (TCP_SKB_CB(skb)->ack_seq != tp->snd_nxt)
			goto reset_and_undo;

		if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr &&
		    !between(tp->rx_opt.rcv_tsecr, tp->retrans_stamp,
			     tcp_time_stamp)) {
			NET_INC_STATS_BH(LINUX_MIB_PAWSACTIVEREJECTED);
			goto reset_and_undo;
		}

		/* Now ACK is acceptable.
		 *
		 * "If the RST bit is set
		 *    If the ACK was acceptable then signal the user "error:
		 *    connection reset", drop the segment, enter CLOSED state,
		 *    delete TCB, and return."
		 */

		if (th->rst) {
			tcp_reset(sk);
			goto discard;
		}

		/* rfc793:
		 *   "fifth, if neither of the SYN or RST bits is set then
		 *    drop the segment and return."
		 *
		 *    See note below!
		 *                                        --ANK(990513)
		 */
		if (!th->syn)
			goto discard_and_undo;

		/* rfc793:
		 *   "If the SYN bit is on ...
		 *    are acceptable then ...
		 *    (our SYN has been ACKed), change the connection
		 *    state to ESTABLISHED..."
		 */

		TCP_ECN_rcv_synack(tp, th);

		tp->snd_wl1 = TCP_SKB_CB(skb)->seq;
		tcp_ack(sk, skb, FLAG_SLOWPATH);

		/* Ok.. it's good. Set up sequence numbers and
		 * move to established.
		 */
		tp->rcv_nxt = TCP_SKB_CB(skb)->seq + 1;
		tp->rcv_wup = TCP_SKB_CB(skb)->seq + 1;

		/* RFC1323: The window in SYN & SYN/ACK segments is
		 * never scaled.
		 */
		tp->snd_wnd = ntohs(th->window);
		tcp_init_wl(tp, TCP_SKB_CB(skb)->ack_seq, TCP_SKB_CB(skb)->seq);

		if (!tp->rx_opt.wscale_ok) {
			tp->rx_opt.snd_wscale = tp->rx_opt.rcv_wscale = 0;
			tp->window_clamp = min(tp->window_clamp, 65535U);
		}

		if (tp->rx_opt.saw_tstamp) 
		{
			tp->rx_opt.tstamp_ok	   = 1;
			tp->tcp_header_len = sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
			tp->advmss	    -= TCPOLEN_TSTAMP_ALIGNED;
			tcp_store_ts_recent(tp);
		} 
		else 
		{
			tp->tcp_header_len = sizeof(struct tcphdr);
		}

		if (tcp_is_sack(tp) && sysctl_tcp_fack)
			tcp_enable_fack(tp);

		tcp_mtup_init(sk);
		tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		tcp_initialize_rcv_mss(sk);

		/* Remember, tcp_poll() does not lock socket!
		 * Change state from SYN-SENT only after copied_seq
		 * is initialized. */
		tp->copied_seq = tp->rcv_nxt;
		smp_mb();
		tcp_set_state(sk, TCP_ESTABLISHED);

		security_inet_conn_established(sk, skb);

		/* Make sure socket is routed, for correct metrics.  */
		icsk->icsk_af_ops->rebuild_header(sk);

		tcp_init_metrics(sk);

		tcp_init_congestion_control(sk);

		/* Prevent spurious tcp_cwnd_restart() on first data
		 * packet.
		 */
		tp->lsndtime = tcp_time_stamp;

		tcp_init_buffer_space(sk);

		if (sock_flag(sk, SOCK_KEEPOPEN))
			inet_csk_reset_keepalive_timer(sk, keepalive_time_when(tp));

		if (!tp->rx_opt.snd_wscale)
			__tcp_fast_path_on(tp, tp->snd_wnd);
		else
			tp->pred_flags = 0;

		if (!sock_flag(sk, SOCK_DEAD)) {
			sk->sk_state_change(sk);
			sk_wake_async(sk, 0, POLL_OUT);
		}

		if (sk->sk_write_pending ||
		    icsk->icsk_accept_queue.rskq_defer_accept ||
		    icsk->icsk_ack.pingpong) {
			/* Save one ACK. Data will be ready after
			 * several ticks, if write_pending is set.
			 *
			 * It may be deleted, but with this feature tcpdumps
			 * look so _wonderfully_ clever, that I was not able
			 * to stand against the temptation 8)     --ANK
			 */
			inet_csk_schedule_ack(sk);
			icsk->icsk_ack.lrcvtime = tcp_time_stamp;
			icsk->icsk_ack.ato	 = TCP_ATO_MIN;
			tcp_incr_quickack(sk);
			tcp_enter_quickack_mode(sk);
			inet_csk_reset_xmit_timer(sk, ICSK_TIME_DACK,
						  TCP_DELACK_MAX, TCP_RTO_MAX);

discard:
			__kfree_skb(skb);
			return 0;
		} else {
			tcp_send_ack(sk);
		}
		return -1;
	}

	/* No ACK in the segment */

	if (th->rst) {
		/* rfc793:
		 * "If the RST bit is set
		 *
		 *      Otherwise (no ACK) drop the segment and return."
		 */

		goto discard_and_undo;
	}

	/* PAWS check. */
	if (tp->rx_opt.ts_recent_stamp && tp->rx_opt.saw_tstamp && tcp_paws_check(&tp->rx_opt, 0))
		goto discard_and_undo;

	if (th->syn)
	{
		/* We see SYN without ACK. It is attempt of
		 * simultaneous connect with crossed SYNs.
		 * Particularly, it can be connect to self.
		 */
		tcp_set_state(sk, TCP_SYN_RECV);

		if (tp->rx_opt.saw_tstamp)
		{
			tp->rx_opt.tstamp_ok = 1;
			tcp_store_ts_recent(tp);
			tp->tcp_header_len = sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
		}
		else 
		{
			tp->tcp_header_len = sizeof(struct tcphdr);
		}

		tp->rcv_nxt = TCP_SKB_CB(skb)->seq + 1;
		tp->rcv_wup = TCP_SKB_CB(skb)->seq + 1;

		/* RFC1323: The window in SYN & SYN/ACK segments is
		 * never scaled.
		 */
		tp->snd_wnd    = ntohs(th->window);
		tp->snd_wl1    = TCP_SKB_CB(skb)->seq;
		tp->max_window = tp->snd_wnd;

		TCP_ECN_rcv_syn(tp, th);

		tcp_mtup_init(sk);
		tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		tcp_initialize_rcv_mss(sk);


		tcp_send_synack(sk);
#if 0
		/* Note, we could accept data and URG from this segment.
		 * There are no obstacles to make this.
		 *
		 * However, if we ignore data in ACKless segments sometimes,
		 * we have no reasons to accept it sometimes.
		 * Also, seems the code doing it in step6 of tcp_rcv_state_process
		 * is not flawless. So, discard packet for sanity.
		 * Uncomment this return to process the data.
		 */
		return -1;
#else
		goto discard;
#endif
	}
	/* "fifth, if neither of the SYN or RST bits is set then
	 * drop the segment and return."
	 */

discard_and_undo:
	tcp_clear_options(&tp->rx_opt);
	tp->rx_opt.mss_clamp = saved_clamp;
	goto discard;

reset_and_undo:
	tcp_clear_options(&tp->rx_opt);
	tp->rx_opt.mss_clamp = saved_clamp;
	return 1;
}


/*
 *	This function implements the receiving procedure of RFC 793 for
 *	all states except ESTABLISHED and TIME_WAIT.
 *	It's called from both tcp_v4_rcv and tcp_v6_rcv and should be
 *	address independent.
 */

int tcp_rcv_state_process(struct sock *sk, struct sk_buff *skb, struct tcphdr *th, unsigned len)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int queued = 0;

	tp->rx_opt.saw_tstamp = 0;

	switch (sk->sk_state)
	{
	case TCP_CLOSE:
		goto discard;

	case TCP_LISTEN:
		if (th->ack)
			return 1;

		if (th->rst)
			goto discard;

		if (th->syn) 
		{
			if (icsk->icsk_af_ops->conn_request(sk, skb) < 0)
				return 1;

			/* Now we have several options: In theory there is
			 * nothing else in the frame. KA9Q has an option to
			 * send data with the syn, BSD accepts data with the
			 * syn up to the [to be] advertised window and
			 * Solaris 2.1 gives you a protocol error. For now
			 * we just ignore it, that fits the spec precisely
			 * and avoids incompatibilities. It would be nice in
			 * future to drop through and process the data.
			 *
			 * Now that TTCP is starting to be used we ought to
			 * queue this data.
			 * But, this leaves one open to an easy denial of
			 * service attack, and SYN cookies can't defend
			 * against this problem. So, we drop the data
			 * in the interest of security over speed unless
			 * it's still in use.
			 */
			kfree_skb(skb);
			return 0;
		}
		goto discard;

	case TCP_SYN_SENT:
		queued = tcp_rcv_synsent_state_process(sk, skb, th, len);
		if (queued >= 0)
			return queued;

		/* Do step6 onward by hand. */
		tcp_urg(sk, skb, th);
		__kfree_skb(skb);
		tcp_data_snd_check(sk);
		return 0;
	}

	if (tcp_fast_parse_options(skb, th, tp) && tp->rx_opt.saw_tstamp &&
	    tcp_paws_discard(sk, skb)) {
		if (!th->rst) {
			NET_INC_STATS_BH(LINUX_MIB_PAWSESTABREJECTED);
			tcp_send_dupack(sk, skb);
			goto discard;
		}
		/* Reset is accepted even if it did not pass PAWS. */
	}

	/* step 1: check sequence number */
	if (!tcp_sequence(tp, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq))
	{
		if (!th->rst)
			tcp_send_dupack(sk, skb);
		goto discard;
	}

	/* step 2: check RST bit */
	if (th->rst) {
		tcp_reset(sk);
		goto discard;
	}

	tcp_replace_ts_recent(tp, TCP_SKB_CB(skb)->seq);

	/* step 3: check security and precedence [ignored] */

	/*	step 4:
	 *
	 *	Check for a SYN in window.
	 */
	if (th->syn && !before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {
		NET_INC_STATS_BH(LINUX_MIB_TCPABORTONSYN);
		tcp_reset(sk);
		return 1;
	}

	/* step 5: check the ACK field */
	if (th->ack)
	{
		int acceptable = tcp_ack(sk, skb, FLAG_SLOWPATH);

		switch (sk->sk_state) {
		case TCP_SYN_RECV:
			if (acceptable) 
			{
				tp->copied_seq = tp->rcv_nxt;
				smp_mb();
				tcp_set_state(sk, TCP_ESTABLISHED);
				sk->sk_state_change(sk);

				/* Note, that this wakeup is only for marginal
				 * crossed SYN case. Passively open sockets
				 * are not waked up, because sk->sk_sleep ==
				 * NULL and sk->sk_socket == NULL.
				 */
				if (sk->sk_socket) {
					sk_wake_async(sk,0,POLL_OUT);
				}

				tp->snd_una = TCP_SKB_CB(skb)->ack_seq;
				tp->snd_wnd = ntohs(th->window) <<
					      tp->rx_opt.snd_wscale;
				tcp_init_wl(tp, TCP_SKB_CB(skb)->ack_seq, TCP_SKB_CB(skb)->seq);

				/* tcp_ack considers this ACK as duplicate
				 * and does not calculate rtt.
				 * Fix it at least with timestamps.
				 */
				if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr &&
				    !tp->srtt)
					tcp_ack_saw_tstamp(sk, 0);

				if (tp->rx_opt.tstamp_ok)
					tp->advmss -= TCPOLEN_TSTAMP_ALIGNED;

				/* Make sure socket is routed, for
				 * correct metrics.
				 */
				icsk->icsk_af_ops->rebuild_header(sk);

				tcp_init_metrics(sk);

				tcp_init_congestion_control(sk);

				/* Prevent spurious tcp_cwnd_restart() on
				 * first data packet.
				 */
				tp->lsndtime = tcp_time_stamp;

				tcp_mtup_init(sk);
				tcp_initialize_rcv_mss(sk);
				tcp_init_buffer_space(sk);
				tcp_fast_path_on(tp);
			}
			else 
			{
				return 1;
			}
			break;

		case TCP_FIN_WAIT1:
			if (tp->snd_una == tp->write_seq) {
				tcp_set_state(sk, TCP_FIN_WAIT2);
				sk->sk_shutdown |= SEND_SHUTDOWN;
				dst_confirm(sk->sk_dst_cache);

				if (!sock_flag(sk, SOCK_DEAD))
					/* Wake up lingering close() */
					sk->sk_state_change(sk);
				else {
					int tmo;

					if (tp->linger2 < 0 ||
					    (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
					     after(TCP_SKB_CB(skb)->end_seq - th->fin, tp->rcv_nxt))) {
						tcp_done(sk);
						NET_INC_STATS_BH(LINUX_MIB_TCPABORTONDATA);
						return 1;
					}

					tmo = tcp_fin_time(sk);
					if (tmo > TCP_TIMEWAIT_LEN) {
						inet_csk_reset_keepalive_timer(sk, tmo - TCP_TIMEWAIT_LEN);
					} else if (th->fin || sock_owned_by_user(sk)) {
						/* Bad case. We could lose such FIN otherwise.
						 * It is not a big problem, but it looks confusing
						 * and not so rare event. We still can lose it now,
						 * if it spins in bh_lock_sock(), but it is really
						 * marginal case.
						 */
						inet_csk_reset_keepalive_timer(sk, tmo);
					} else {
						tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
						goto discard;
					}
				}
			}
			break;

		case TCP_CLOSING:
			if (tp->snd_una == tp->write_seq) {
				tcp_time_wait(sk, TCP_TIME_WAIT, 0);
				goto discard;
			}
			break;

		case TCP_LAST_ACK:
			if (tp->snd_una == tp->write_seq) {
				tcp_update_metrics(sk);
				tcp_done(sk);
				goto discard;
			}
			break;
		}
	} else
		goto discard;

	/* step 6: check the URG bit */
	tcp_urg(sk, skb, th);

	/* step 7: process the segment text */
	switch (sk->sk_state) {
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_LAST_ACK:
		if (!before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt))
			break;
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
		/* RFC 793 says to queue data in these states,
		 * RFC 1122 says we MUST send a reset.
		 * BSD 4.4 also does reset.
		 */
		if (sk->sk_shutdown & RCV_SHUTDOWN) {
			if (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
			    after(TCP_SKB_CB(skb)->end_seq - th->fin, tp->rcv_nxt)) {
				NET_INC_STATS_BH(LINUX_MIB_TCPABORTONDATA);
				tcp_reset(sk);
				return 1;
			}
		}
		/* Fall through */
	case TCP_ESTABLISHED:
		tcp_data_queue(sk, skb);
		queued = 1;
		break;
	}

	/* tcp_data could move socket to TIME-WAIT */
	if (sk->sk_state != TCP_CLOSE) {
		tcp_data_snd_check(sk);
		tcp_ack_snd_check(sk);
	}

	if (!queued) {
discard:
		__kfree_skb(skb);
	}
	return 0;
}

EXPORT_SYMBOL(sysctl_tcp_ecn);
EXPORT_SYMBOL(sysctl_tcp_reordering);
EXPORT_SYMBOL(tcp_parse_options);
EXPORT_SYMBOL(tcp_rcv_established);
EXPORT_SYMBOL(tcp_rcv_state_process);
EXPORT_SYMBOL(tcp_initialize_rcv_mss);
