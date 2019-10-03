/*
 *	Copied from Linux Monitor (LiMon) - Networking.
 *
 *	Copyright 1994 - 2000 Neil Russell.
 *	(See License)
 *	Copyright 2000 Roland Borde
 *	Copyright 2000 Paolo Scaffardi
 *	Copyright 2000, 2001 Wolfgang Denk
 * 
 * (C) Copyright 2002
 * Sysgo Real-Time Solutions, GmbH <www.elinos.com>
 * Marius Groeger <mgroeger@sysgo.de>
 */

/*
 * General Desription:
 *
 * The user interface supports commands for BOOTP, RARP, and TFTP.
 * Also, we support ARP internally. Depending on available data,
 * these interact as follows:
 *
 * BOOTP:
 *
 *	Prerequisites:	- own ethernet address
 *	We want:	- own IP address
 *			- TFTP server IP address
 *			- name of bootfile
 *	Next step:	ARP
 *
 * RARP:
 *
 *	Prerequisites:	- own ethernet address
 *	We want:	- own IP address
 *			- TFTP server IP address
 *	Next step:	ARP
 *
 * ARP:
 *
 *	Prerequisites:	- own ethernet address
 *			- own IP address
 *			- TFTP server IP address
 *	We want:	- TFTP server ethernet address
 *	Next step:	TFTP
 *
 * DHCP:
 *
 *     Prerequisites:   - own ethernet address
 *     We want:         - IP, Netmask, ServerIP, Gateway IP
 *                      - bootfilename, lease time
 *     Next step:       - TFTP
 *
 * TFTP:
 *
 *	Prerequisites:	- own ethernet address
 *			- own IP address
 *			- TFTP server IP address
 *			- TFTP server ethernet address
 *			- name of bootfile (if unknown, we use a default name
 *			  derived from our own IP address)
 *	We want:	- load the boot file
 *	Next step:	none
 */


#include <armboot.h>
#include <command.h>
#include "net.h"
#include "bootp.h"
#include "tftp.h"
#include "rarp.h"
#include "arp.h"

#if (CONFIG_COMMANDS & CFG_CMD_NET)

#if 0
#define ET_DEBUG
#endif

/** BOOTP EXTENTIONS **/

IPaddr_t	NetOurSubnetMask=0;		/* Our subnet mask (0=unknown)	*/
IPaddr_t	NetOurGatewayIP=0;		/* Our gateways IP address	*/
IPaddr_t	NetOurDNSIP=0;			/* Our DNS IP address		*/
char		NetOurNISDomain[32]={0,};	/* Our NIS domain		*/
char		NetOurHostName[32]={0,};	/* Our hostname			*/
char		NetOurRootPath[64]={0,};	/* Our bootpath			*/
ushort		NetBootFileSize=0;		/* Our bootfile size in blocks	*/

/** END OF BOOTP EXTENTIONS **/

ulong		NetBootFileXferSize;	/* The actual transferred size of the bootfile (in bytes) */
uchar		NetOurEther[6];		/* Our ethernet address			*/
uchar		NetServerEther[6] =	/* Boot server enet address		*/
			{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
IPaddr_t	NetOurIP;		/* Our IP addr (0 = unknown)		*/
IPaddr_t	NetServerIP;		/* Our IP addr (0 = unknown)		*/
volatile uchar *NetRxPkt;		/* Current receive packet		*/
int		NetRxPktLen;		/* Current rx packet length		*/
unsigned	NetIPID;		/* IP packet ID				*/
uchar		NetBcastAddr[6] =	/* Ethernet bcast address		*/
			{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
int		NetState;		/* Network loop state			*/


char		BootFile[128];		/* Boot File name			*/

volatile uchar	PktBuf[(PKTBUFSRX+1) * PKTSIZE_ALIGN + PKTALIGN];

volatile uchar *NetRxPackets[PKTBUFSRX]; /* Receive packets			*/

static rxhand_f *packetHandler;		/* Current RX packet handler		*/
static thand_f *timeHandler;		/* Current timeout handler		*/
static ulong	timeValue;		/* Current timeout value		*/
volatile uchar *NetTxPacket = 0;	/* THE transmit packet			*/
bd_t	       *Net_bd;
static int net_check_prereq (proto_t protocol);


#ifdef ET_DEBUG
void		hexdump(uchar * data, unsigned long size);
#endif

void		NetPrintEther(volatile uchar * addr);

/**********************************************************************/
/*
 *	Main network processing loop.
 */

int
NetLoop(bd_t *bis, proto_t protocol)
{
	char	*s, *e;
	ulong	reg;

  	Net_bd = bis;
	if (!NetTxPacket) {
		int	i;

		/*
		 *	Setup packet buffers, aligned correctly.
		 */
		NetTxPacket = &PktBuf[0] + (PKTALIGN - 1);
		NetTxPacket -= (ulong)NetTxPacket % PKTALIGN;
		for (i = 0; i < PKTBUFSRX; i++) {
			NetRxPackets[i] = NetTxPacket + (i+1)*PKTSIZE_ALIGN;
		}
	}

	eth_halt();
	eth_init(bis);

	NetCopyEther(NetOurEther, bis->bi_enetaddr);

restart:
	NetState = NETLOOP_CONTINUE;

	/*
	 *	Start the ball rolling with the given start function.  From
	 *	here on, this code is a state machine driven by received
	 *	packets and timer events.
	 */

	if (protocol == TFTP) {			/* TFTP */
		NetOurIP = bis->bi_ip_addr;
		NetServerIP = 0;
		s = getenv (bis, "serverip");
		for (reg=0; reg<4; ++reg) {
			ulong val = s ? simple_strtoul(s, &e, 10) : 0;
			NetServerIP <<= 8;
			NetServerIP |= (val & 0xFF);
			if (s) s = (*e) ? e+1 : e;
		}

		if (net_check_prereq (protocol) != 0) {
			return 0;
		}

		/* always use ARP to get server ethernet address */
		ArpTry = 0;
		ArpRequest ();

#if (CONFIG_COMMANDS & CFG_CMD_DHCP)
	} else if (protocol == DHCP) {
		if (net_check_prereq (protocol) != 0) {
			return 0;
		}

		/* Start with a clean slate... */
		NetOurIP = 0;
		NetServerIP = 0;
		DhcpRequest();		/* Basically same as BOOTP */

#endif	/* CFG_CMD_DHCP */

	} else {				/* BOOTP or RARP */

		/*
                 * initialize our IP addr to 0 in order to accept ANY
                 * IP addr assigned to us by the BOOTP / RARP server
		 */
		NetOurIP = 0;
		NetServerIP = 0;

		if (net_check_prereq (protocol) != 0) {
			return 0;
		}

		if (protocol == BOOTP) {
			BootpTry = 0;
			BootpRequest ();
		} else {
			RarpTry	 = 0;
			RarpRequest ();
		}
	}

	NetBootFileXferSize = 0;

	/*
	 *	Main packet reception loop.  Loop receiving packets until
	 *	someone sets `NetQuit'.
	 */
	for (;;) {
		/*
		 *	Check the ethernet for a new packet.  The ethernet
		 *	receive routine will process it.
		 */
			eth_rx();

		/*
		 *	Abort if ctrl-c was pressed.
		 */
		if (ctrlc()) {
		        eth_halt();
			printf("\nAbort\n");
			return 0;
		}


		/*
		 *	Check for a timeout, and run the timeout handler
		 *	if we have one.
		 */
		if (timeHandler && (get_timer(0) > timeValue)) {
			thand_f *x;

			x = timeHandler;
			timeHandler = (thand_f *)0;
			(*x)();
		}


		switch (NetState) {

		case NETLOOP_RESTART:
			goto restart;

		case NETLOOP_SUCCESS:
			if (NetBootFileXferSize > 0) {
				char buf[10];
				printf("Bytes transferred = %ld (%lx hex)\n",
					NetBootFileXferSize,
					NetBootFileXferSize);
				sprintf(buf, "%lx", NetBootFileXferSize);
				setenv(bis, "filesize", buf);
			}
			eth_halt();
			return 1;

		case NETLOOP_FAIL:
			return 0;
		}
	}
}

/**********************************************************************/

static void
startAgainTimeout(void)
{
	NetState = NETLOOP_RESTART;
}


static void
startAgainHandler(uchar * pkt, unsigned dest, unsigned src, unsigned len)
{
	/* Totally ignore the packet */
}


void
NetStartAgain(void)
{
	NetSetTimeout(10 * CFG_HZ, startAgainTimeout);
	NetSetHandler(startAgainHandler);
}

/**********************************************************************/
/*
 *	Miscelaneous bits.
 */

void
NetSetHandler(rxhand_f * f)
{
	packetHandler = f;
}


void
NetSetTimeout(int iv, thand_f * f)
{
	if (iv == 0) {
		timeHandler = (thand_f *)0;
	} else {
		timeHandler = f;
		timeValue = get_timer(0) + iv;
	}
}


void
NetSendPacket(volatile uchar * pkt, int len)
{
	(void) eth_send(pkt, len);
}



void
NetReceive(volatile uchar * pkt, int len)
{
	Ethernet_t *et;
	IP_t	*ip;
	ARP_t	*arp;
	int	x;

	NetRxPkt = pkt;
	NetRxPktLen = len;
	et = (Ethernet_t *)pkt;

	x = SWAP16(et->et_protlen);

	if (x < 1514) {
		/*
		 *	Got a 802 packet.  Check the other protocol field.
		 */
		x = SWAP16(et->et_prot);
		ip = (IP_t *)(pkt + E802_HDR_SIZE);
		len -= E802_HDR_SIZE;
#ifdef ET_DEBUG
		printf("Receive 802 type ET, protocol 0x%x\n", x);
#endif

	} else {
		ip = (IP_t *)(pkt + ETHER_HDR_SIZE);
		len -= ETHER_HDR_SIZE;
#ifdef ET_DEBUG
		printf("Receive non-802 type ET\n");
#endif
	}

	switch (x) {

	case PROT_ARP:
		/*
		 * We have to deal with two types of ARP packets:
                 * - REQUEST packets will be answered by sending  our
                 *   IP address - if we know it.
                 * - REPLY packates are expected only after we asked
                 *   for the TFTP server's or the gateway's ethernet
                 *   address; so if we receive such a packet, we set
                 *   the server ethernet address
		 */
#ifdef ET_DEBUG
		printf("Got ARP\n");
#endif
		arp = (ARP_t *)ip;
		if (len < ARP_HDR_SIZE) {
			printf("bad length %d < %d\n", len, ARP_HDR_SIZE);
			return;
		}
		if (SWAP16(arp->ar_hrd) != ARP_ETHER) {
			return;
		}
		if (SWAP16(arp->ar_pro) != PROT_IP) {
			return;
		}
		if (arp->ar_hln != 6) {
			return;
		}
		if (arp->ar_pln != 4) {
			return;
		}

		if (NetOurIP == 0) {
#ifdef ET_DEBUG
			printf("We don't know our own IP -> Nothing to do\n");
#endif
			return;
		}

		
		{
			IPaddr_t ip = NetReadIP((uchar*)&arp->ar_data[16]);
			if (ip != NetOurIP) {
#ifdef ET_DEBUG
				printf("Requested IP is not ours\n");
#endif			
				return;
			}
		}

		switch (SWAP16(arp->ar_op)) {
		case ARPOP_REQUEST:		/* reply with our Ether address	*/
#ifdef ET_DEBUG
			printf("Got ARP REQUEST, return our EtherAddr.\n");
#endif
			NetSetEther((uchar *)et, et->et_src, PROT_ARP);
			arp->ar_op = SWAP16(ARPOP_REPLY);
			NetCopyEther(&arp->ar_data[0],  NetOurEther);
			NetWriteIP(  &arp->ar_data[6],  NetOurIP);
			NetCopyEther(&arp->ar_data[10], NetOurEther);
			NetWriteIP(  &arp->ar_data[16], NetOurIP);
			NetSendPacket((uchar *)et,((uchar *)arp-pkt)+ARP_HDR_SIZE);
			return;
		case ARPOP_REPLY:		/* set TFTP server eth addr	*/
#ifdef ET_DEBUG
			printf("Got ARP REPLY, set server/gtwy eth addr\n");
#endif
			/* check if target ether is ours */
			if ( memcmp(NetOurEther, &(arp->ar_data[10]), 6) != 0 )
			{
#ifdef ET_DEBUG
				printf("  Reply is not for us. Ignoring it...\n");
#endif
				return;
			}			
			NetCopyEther(NetServerEther, &arp->ar_data[0]);
			printf("eth addr: ");
			NetPrintEther(NetServerEther);
			(*packetHandler)(0,0,0,0);	/* start TFTP */
			return;
		default:
#ifdef ET_DEBUG
			printf("Unexpected ARP opcode 0x%x\n", SWAP16(arp->ar_op));
#endif
			return;
		}

	case PROT_RARP:
#ifdef ET_DEBUG
		printf("Got RARP\n");
#endif
		arp = (ARP_t *)ip;
		if (len < ARP_HDR_SIZE) {
			printf("bad length %d < %d\n", len, ARP_HDR_SIZE);
			return;
		}

		if ((SWAP16(arp->ar_op) != RARPOP_REPLY) ||
			(SWAP16(arp->ar_hrd) != ARP_ETHER)   ||
			(SWAP16(arp->ar_pro) != PROT_IP)     ||
			(arp->ar_hln != 6) || (arp->ar_pln != 4)) {

			printf("invalid RARP header\n");
		} else {
			NetOurIP = NetReadIP((uchar*)&arp->ar_data[16]);
			NetServerIP = NetReadIP((uchar*)&arp->ar_data[6]);
			NetCopyEther(NetServerEther, &arp->ar_data[0]);

			(*packetHandler)(0,0,0,0);
		}
		break;

	case PROT_IP:
#ifdef ET_DEBUG
		printf("Got IP\n");
#endif
		if (len < IP_HDR_SIZE) {
			debug ("len bad %d < %d\n", len, IP_HDR_SIZE);
			return;
		}
		if (len < SWAP16(ip->ip_len)) {
			printf("len bad %d < %d\n", len, SWAP16(ip->ip_len));
			return;
		}
		len = SWAP16(ip->ip_len);
#ifdef ET_DEBUG
		printf("len=%d, v=%02x\n", len, ip->ip_hl_v & 0xff);
#endif
		if ((ip->ip_hl_v & 0xf0) != 0x40) {
			printf("version bad %x\n", ip->ip_hl_v & 0xf0);
			return;
		}
		if (ip->ip_off & SWAP16c(0x1fff)) { /* Can't deal w/ fragments */
			printf("can't deal with fragments\n");
			return;
		}
		if (!NetCksumOk((uchar *)ip, IP_HDR_SIZE_NO_UDP / 2)) {
			printf("checksum bad\n");
			return;
		}
		if (NetOurIP) {
		    IPaddr_t ipaddr = NetReadIP((uchar*)&ip->ip_dst);
		    if (ipaddr != NetOurIP && ipaddr != 0xFFFFFFFF)
		    {
#ifdef ET_DEBUG
			printf("ip packet not for us\n");
			print_IPaddr(ipaddr);
#endif
			return;
		    }
		}
		/*
		 * watch for ICMP host redirects
		 *
                 * There is no real handler code (yet). We just watch
                 * for ICMP host redirect messages. In case anybody
                 * sees these messages: please contact me
                 * (wd@denx.de), or - even better - send me the
                 * necessary fixes :-)
		 *
                 * Note: in all cases where I have seen this so far
                 * it was a problem with the router configuration,
                 * for instance when a router was configured in the
                 * BOOTP reply, but the TFTP server was on the same
                 * subnet. So this is probably a warning that your
                 * configuration might be wrong. But I'm not really
                 * sure if there aren't any other situations.
		 */
		if (ip->ip_p == IPPROTO_ICMP) {
			ICMP_t *icmph = (ICMP_t *)&(ip->udp_src);

			if (icmph->type != ICMP_REDIRECT)
				return;
			if (icmph->code != ICMP_REDIR_HOST)
				return;
			puts (" ICMP Host Redirect to ");
			print_IPaddr(icmph->un.gateway);
			putc(' ');
		} else if (ip->ip_p != IPPROTO_UDP) {	/* Only UDP packets */
			return;
		}

		/*
		 *	IP header OK.  Pass the packet to the current handler.
		 */
		(*packetHandler)((uchar *)ip +IP_HDR_SIZE,
						SWAP16(ip->udp_dst),
						SWAP16(ip->udp_src),
						SWAP16(ip->udp_len) - 8);

		break;
	default:
#ifdef ET_DEBUG
		printf("Got unknown protocol %04x\n",x);
#endif
	}
}


/**********************************************************************/

static int net_check_prereq (proto_t protocol)
{
	switch (protocol) {
	case ARP:	/* nothing to do */
			break;

	case TFTP:
			if (NetServerIP == 0) {
				puts ("*** ERROR: `serverip' not set\n");
				return (1);
			}

			if (NetOurIP == 0) {
				puts ("*** ERROR: `ipaddr' not set\n");
				return (1);
			}
			/* Fall through */

	case DHCP:
	case RARP:
	case BOOTP:
			if (memcmp(NetOurEther, "\0\0\0\0\0\0", 6) == 0) {
				puts ("*** ERROR: `ethaddr' not set\n");
				return (1);
			}
			/* Fall through */
	}
	return (0);	/* OK */
}
/**********************************************************************/

int
NetCksumOk(uchar * ptr, int len)
{
	return !((NetCksum(ptr, len) + 1) & 0xfffe);
}


unsigned
NetCksum(uchar * ptr, int len)
{
	ulong	xsum;

	xsum = 0;
	while (len-- > 0)
		xsum += *((ushort *)ptr)++;
	xsum = (xsum & 0xffff) + (xsum >> 16);
	xsum = (xsum & 0xffff) + (xsum >> 16);
	return (xsum & 0xffff);
}


void
NetCopyEther(volatile uchar * to, uchar * from)
{
	int	i;

	for (i = 0; i < 6; i++)
		*to++ = *from++;
}

void
NetWriteIP(volatile uchar * to, IPaddr_t ip)
{
	int	i;

	for (i = 0; i < 4; i++) 
	{
		*to++ = ip >> 24;
	    	ip <<= 8;
	}
}

IPaddr_t
NetReadIP(volatile uchar * from)
{
	IPaddr_t ip;
	int i;

	ip = 0;
	for (i = 0; i < 4; i++) 
		ip = (ip << 8) | *from++;

	return ip;
}

void
NetCopyIP(volatile uchar * to, volatile uchar *from)
{
	int i;
	for (i = 0; i < 4; i++) 
		*to++ = *from++;
}

void
NetSetEther(volatile uchar * xet, uchar * addr, uint prot)
{
	volatile Ethernet_t *et = (Ethernet_t *)xet;

	NetCopyEther(et->et_dest, addr);
	NetCopyEther(et->et_src, NetOurEther);
	et->et_protlen = SWAP16(prot);
}


void
NetSetIP(volatile uchar * xip, IPaddr_t dest, int dport, int sport, int len)
{
	volatile IP_t *ip = (IP_t *)xip;

	/*
	 *	If the data is an odd number of bytes, zero the
	 *	byte after the last byte so that the checksum
	 *	will work.
	 */
	if (len & 1)
		xip[IP_HDR_SIZE + len] = 0;

	/*
	 *	Construct an IP and UDP header.
			(need to set no fragment bit - XXX)
	 */
	ip->ip_hl_v  = 0x45;		/* IP_HDR_SIZE / 4 (not including UDP) */
	ip->ip_tos   = 0;
	ip->ip_len   = SWAP16(IP_HDR_SIZE + len);
	ip->ip_id    = SWAP16(NetIPID++);
	ip->ip_off   = SWAP16c(0x4000);	/* No fragmentation */
	ip->ip_ttl   = 255;
	ip->ip_p     = 17;		/* UDP */
	ip->ip_sum   = 0;
	NetWriteIP((uchar*)&ip->ip_src, NetOurIP);
	NetWriteIP((uchar*)&ip->ip_dst, dest);
	ip->udp_src  = SWAP16(sport);
	ip->udp_dst  = SWAP16(dport);
	ip->udp_len  = SWAP16(8 + len);
	ip->udp_xsum = 0;
	ip->ip_sum   = ~NetCksum((uchar *)ip, IP_HDR_SIZE_NO_UDP / 2);
}

void copy_filename (uchar *dst, uchar *src, int size)
{
	if (*src && (*src == '"')) {
		++src;
		--size;
	}

	while ((--size > 0) && *src && (*src != '"')) {
		*dst++ = *src++;
	}
	*dst = '\0';
}

#endif /* CFG_CMD_NET */

void ip_to_string (IPaddr_t x, char *s)
{
    sprintf (s,"%d.%d.%d.%d",
    	(int)((x >> 24) & 0xff),
	(int)((x >> 16) & 0xff),
	(int)((x >>  8) & 0xff),
	(int)((x >>  0) & 0xff)
    );
}

void print_IPaddr (IPaddr_t x)
{
    char tmp[12];

    ip_to_string(x, tmp);

    puts(tmp);
}


void
NetPrintEther(volatile uchar * addr)
{
	int	i;
	
	for (i = 0; i < 6; i++)
	{
		printf("%02x", *(addr+i));
		if (i != 5)
			printf(":");
	}
	printf("\n");
}

#ifdef ET_DEBUG
void
hexdump(uchar * data, unsigned long size)
{
	unsigned long i = 0;
	for (i = 0; i < size; i++)
	{
		if ( ((i % 16) == 0) && (i != 0) )
		{
			printf("\n");
		}
		printf("%02x  ", *(data+i));
	}
	printf("\n\n");
}
#endif /* ET_DEBUG */
