/*
 *	Based on LiMon - BOOTP.
 *
 *	Copyright 1994, 1995, 2000 Neil Russell.
 *	(See License)
 *	Copyright 2000 Roland Borde
 *	Copyright 2000 Paolo Scaffardi
 *
 * (C) Copyright 2002
 * Sysgo Real-Time Solutions, GmbH <www.elinos.com>
 * Marius Groeger <mgroeger@sysgo.de>
 */

#if 0
#define	DEBUG		1	/* general debug */
#define DEBUG_BOOTP_EXT	1	/* Debug received vendor fields	*/
#endif

#ifdef DEBUG_BOOTP_EXT
#define debug_ext(fmt,args...)	printf (fmt ,##args)
#else
#define debug_ext(fmt,args...)
#endif

#include <armboot.h>
#include <command.h>
#include "net.h"
#include "bootp.h"
#include "tftp.h"
#include "arp.h"
#ifdef CONFIG_STATUS_LED
#include <status_led.h>
#endif

#define	BOOTP_VENDOR_MAGIC	0x63825363 	/* RFC1048 Magic Cookie 	*/

#if (CONFIG_COMMANDS & CFG_CMD_NET)

#define TIMEOUT		5		/* Seconds before trying BOOTP again	*/

#define PORT_BOOTPS	67		/* BOOTP server UDP port		*/
#define PORT_BOOTPC	68		/* BOOTP client UDP port		*/

ulong		BootpID;
int		BootpTry;
#ifdef CONFIG_BOOTP_RANDOM_DELAY
ulong		seed1, seed2;
#endif

#if (CONFIG_COMMANDS & CFG_CMD_DHCP)
dhcp_state_t dhcp_state = INIT;
unsigned int dhcp_leasetime = 0;
static void DhcpHandler(uchar * pkt, unsigned dest, unsigned src, unsigned len);

/* For Debug */
char *dhcpmsg2str(int type)
{
	switch (type) {
	case 1: return "DHCPDISCOVER"; break;
	case 2: return "DHCPOFFER"; break;
	case 3: return "DHCPREQUEST"; break;
	case 4: return "DHCPDECLINE"; break;
	case 5: return "DHCPACK"; break;
	case 6: return "DHCPNACK"; break;
	case 7: return "DHCPRELEASE"; break;
	default: return "UNKNOWN/INVALID MSG TYPE"; break;
	}
}
#endif

static int BootpCheckPkt(uchar *pkt, unsigned dest, unsigned src, unsigned len)
{
	Bootp_t *bp = (Bootp_t *) pkt;
	int retval = 0;
	ulong id;

	if (dest != PORT_BOOTPC || src != PORT_BOOTPS)
		retval = -1;
	if (len < sizeof (Bootp_t) - OPT_SIZE)
		retval = -2;
	if (bp->bp_op != OP_BOOTREQUEST &&
	    bp->bp_op != OP_BOOTREPLY &&
	    bp->bp_op != DHCP_OFFER &&
	    bp->bp_op != DHCP_ACK &&
	    bp->bp_op != DHCP_NAK ) {
		retval = -3;
	}
	if (bp->bp_htype != HWT_ETHER)
		retval = -4;
	if (bp->bp_hlen != HWL_ETHER)
		retval = -5;
	memcpy(&id, &bp->bp_id, sizeof(bp->bp_id));
	if (id != BootpID)
		retval = -6;

	debug ("Filtering pkt = %d\n", retval);

	return retval;
}

/*
 * Copy parameters of interest from BOOTP_REPLY/DHCP_OFFER packet
 */
void BootpCopyNetParams(Bootp_t *bp)
{
	NetOurIP = NetReadIP((vuchar*)&bp->bp_yiaddr);
	NetServerIP = NetReadIP((vuchar*)&bp->bp_siaddr);
	NetCopyEther(NetServerEther, ((Ethernet_t *)NetRxPkt)->et_src);
	copy_filename (BootFile, bp->bp_file, sizeof(BootFile));

	debug ("Bootfile: %s\n", BootFile);

	/* Propagate to environment */
	setenv (Net_bd, "bootfile", BootFile);
}

static int truncate_sz (const char *name, int maxlen, int curlen)
{
	if (curlen >= maxlen) {
		printf("*** WARNING: %s is too long (%d - max: %d) - truncated\n",
			name, curlen, maxlen);
		curlen = maxlen - 1;
	}
	return (curlen);
}

#if !(CONFIG_COMMANDS & CFG_CMD_DHCP)

static void BootpVendorFieldProcess(u8 *ext)
{
    int size = *(ext+1) ;

    debug_ext ("[BOOTP] Processing extension %d... (%d bytes)\n", *ext, *(ext+1));

    NetBootFileSize = 0;

    switch (*ext) {
    /* Fixed length fields */
	case 1:		/* Subnet mask					*/
		if (NetOurSubnetMask == 0)
		    memcpy(&NetOurSubnetMask, ext+2, 4);
		break;
	case 2:		/* Time offset - Not yet supported		*/
		break;
    /* Variable length fields */
	case 3:		/* Gateways list				*/
		if (NetOurGatewayIP == 0) {
		    memcpy(&NetOurGatewayIP, ext+2, 4);
		}
		break;
	case 4:		/* Time server - Not yet supported		*/
		break;
	case 5:		/* IEN-116 name server - Not yet supported	*/
		break;
	case 6:
		if (NetOurDNSIP == 0) {
		    memcpy(&NetOurDNSIP, ext+2, 4);
		}
		break;
	case 7:		/* Log server - Not yet supported		*/
		break;
	case 8:		/* Cookie/Quote server - Not yet supported	*/
		break;
	case 9:		/* LPR server - Not yet supported		*/
		break;
	case 10:	/* Impress server - Not yet supported		*/
		break;
	case 11:	/* RPL server - Not yet supported		*/
		break;
	case 12:	/* Host name					*/
		if (NetOurHostName[0] == 0) {
		    size = truncate_sz("Host Name", sizeof(NetOurHostName), size);
		    memcpy(&NetOurHostName, ext+2, size);
		    NetOurHostName[size] = 0 ;
		}
		break;
	case 13:	/* Boot file size				*/
		memcpy(&NetBootFileSize, ext+2, size);
		break;
	case 14:	/* Merit dump file - Not yet supported		*/
		break;
	case 15:	/* Domain name - Not yet supported		*/
		break;
	case 16:	/* Swap server - Not yet supported		*/
		break;
	case 17:	/* Root path					*/
		if (NetOurRootPath[0] == 0) {
		    size = truncate_sz("Root Path", sizeof(NetOurRootPath), size);
		    memcpy(&NetOurRootPath, ext+2, size);
		    NetOurRootPath[size] = 0 ;
		}
		break;
	case 18:	/* Extension path - Not yet supported		*/
		/*
                 * This can be used to send the informations of the
                 * vendor area in another file that the client can
                 * access via TFTP.
		 */
		break;
    /* IP host layer fields */
	case 40:	/* NIS Domain name				*/
		if (NetOurNISDomain[0] == 0) {
		    size = truncate_sz ("NIS Domain Name",
		    			sizeof(NetOurNISDomain),
					size);
		    memcpy(&NetOurNISDomain, ext+2, size);
		    NetOurNISDomain[size] = 0 ;
		}
		break;
    /* Application layer fields */
	case 43:	/* Vendor specific info - Not yet supported	*/
		/*
                 * Binary informations to exchange specific
                 * product information.
		 */
		break;
    /* Reserved (custom) fields (128..254) */
    }
}

static void BootpVendorProcess(u8 *ext, int size)
{
    u8 *end = ext + size ;

    debug_ext ("[BOOTP] Checking extension (%d bytes)...\n", size);

    while ((ext < end) && (*ext != 0xff)) {
	if (*ext == 0) {
	    ext ++ ;
	} else {
		u8 *opt = ext ;
		ext += ext[1] + 2 ;
		if (ext <= end)
		    BootpVendorFieldProcess (opt) ;
	}
    }

#ifdef DEBUG_BOOTP_EXT
    printf("[BOOTP] Received fields: \n");
    if (NetOurSubnetMask) {
	puts ("NetOurSubnetMask	: ");
	print_IPaddr (NetOurSubnetMask);
	putc('\n');
    }

    if (NetOurGatewayIP) {
	puts ("NetOurGatewayIP	: ");
	print_IPaddr (NetOurGatewayIP);
	putc('\n');
    }

    if (NetBootFileSize) {
	printf("NetBootFileSize : %d\n", NetBootFileSize);
    }

    if (NetOurHostName[0]) {
	printf("NetOurHostName  : %s\n", NetOurHostName);
    }

    if (NetOurRootPath[0]) {
	printf("NetOurRootPath  : %s\n", NetOurRootPath);
    }

    if (NetOurNISDomain[0]) {
        printf("NetOurNISDomain : %s\n", NetOurNISDomain);
    }
#endif
}

/*
 *	Handle a BOOTP received packet.
 */
static void
BootpHandler(uchar * pkt, unsigned dest, unsigned src, unsigned len)
{
	Bootp_t *bp;
	char	*s;
	ulong vendmagic;

	debug ("got BOOTP packet (src=%d, dst=%d, len=%d want_len=%d)\n",
		src, dest, len, sizeof (Bootp_t));

	bp = (Bootp_t *)pkt;

	if (BootpCheckPkt(pkt, dest, src, len))	/* Filter out pkts we don't want */
		return;

	/*
	 *	Got a good BOOTP reply.  Copy the data into our variables.
	 */
#ifdef CONFIG_STATUS_LED
	status_led_set (STATUS_LED_BOOT, STATUS_LED_OFF);
#endif

	BootpCopyNetParams(bp);		/* Store net parameters from reply */

	/* Retrieve extended informations (we must parse the vendor area) */
	memcpy(&vendmagic, bp->bp_vend, 4);
	if (SWAP32(vendmagic) == BOOTP_VENDOR_MAGIC)
	    BootpVendorProcess(&bp->bp_vend[4], len);

	NetSetTimeout(0, (thand_f *)0);

	debug ("Got good BOOTP\n");

	if (((s = getenv(Net_bd, "autoload")) != NULL) && (*s == 'n')) {
		/*
		 * Just use BOOTP to configure system;
		 * Do not use TFTP to load the bootfile.
		 */
		NetState = NETLOOP_SUCCESS;
		return;
	}

	/* Send ARP request to get TFTP server ethernet address.
	 * This automagically starts TFTP, too.
	 */
	ArpRequest();
}
#endif	/* !CFG_CMD_DHCP */

/*
 *	Timeout on BOOTP/DHCP request.  Try again, forever.
 */
static void
BootpTimeout(void)
{
	BootpRequest ();
}

/*
 *	Initialize BOOTP extension fields in the request.
 */
#if (CONFIG_COMMANDS & CFG_CMD_DHCP)
static int DhcpExtended(u8 *e, int message_type, IPaddr_t ServerID, IPaddr_t RequestedIP)
{
    u8 *start = e ;
    u8 *cnt;

    *e++ =  99;		/* RFC1048 Magic Cookie */
    *e++ = 130;
    *e++ =  83;
    *e++ =  99;

    *e++ = 53;		/* DHCP Message Type */
    *e++ = 1;
    *e++ = message_type;

    *e++ = 57;		/* Maximum DHCP Message Size */
    *e++ = 2;
    *e++ = (576-312+OPT_SIZE) >> 8;
    *e++ = (576-312+OPT_SIZE) & 0xff;

    if ( ServerID ) {
	    *e++ = 54;	/* ServerID */
	    *e++ = 4;
	    *e++ = ServerID >> 24;
	    *e++ = ServerID >> 16;
	    *e++ = ServerID >> 8;
	    *e++ = ServerID & 0xff;
    }

    if ( RequestedIP ) {
	    *e++ = 50;	/* Requested IP */
	    *e++ = 4;
	    *e++ = RequestedIP >> 24;
	    *e++ = RequestedIP >> 16;
	    *e++ = RequestedIP >> 8;
	    *e++ = RequestedIP & 0xff;
    }

    *e++ = 55;		/* Parameter Request List */
    cnt  = e++;		/* Pointer to count of requested items */
    *cnt = 0;
#if (CONFIG_BOOTP_MASK & CONFIG_BOOTP_SUBNETMASK)
    *e++ = 1;		/* Subnet Mask */
    *cnt += 1;
#endif
#if (CONFIG_BOOTP_MASK & CONFIG_BOOTP_GATEWAY)
    *e++ = 3;		/* Router Option */
    *cnt += 1;
#endif
#if (CONFIG_BOOTP_MASK & CONFIG_BOOTP_DNS)
    *e++ = 6;		/* DNS Server(s) */
    *cnt += 1;
#endif
#if (CONFIG_BOOTP_MASK & CONFIG_BOOTP_HOSTNAME)
    *e++ = 12;		/* Hostname */
    *cnt += 1;
#endif
#if (CONFIG_BOOTP_MASK & CONFIG_BOOTP_BOOTFILESIZE)
    *e++ = 13;		/* Boot File Size */
    *cnt += 1;
#endif
#if (CONFIG_BOOTP_MASK & CONFIG_BOOTP_BOOTPATH)
    *e++ = 17;		/* Boot path */
    *cnt += 1;
#endif
#if (CONFIG_BOOTP_MASK & CONFIG_BOOTP_NISDOMAIN)
    *e++ = 40;		/* NIS Domain name request */
    *cnt += 1;
#endif

    *e++ = 255;		/* End of the list */

    return e - start ;
}

#else	/* CFG_CMD_DHCP */
/*
 *	Warning: no field size check - change CONFIG_BOOTP_MASK at your own risk!
 */
static int BootpExtended (u8 *e)
{
    u8 *start = e ;

    *e++ =  99;		/* RFC1048 Magic Cookie */
    *e++ = 130;
    *e++ =  83;
    *e++ =  99;

#if (CONFIG_COMMANDS & CFG_CMD_DHCP)
    *e++ = 53;		/* DHCP Message Type */
    *e++ = 1;
    *e++ = DHCP_DISCOVER;

    *e++ = 57;		/* Maximum DHCP Message Size */
    *e++ = 2;
    *e++ = (576-312+OPT_SIZE) >> 16;
    *e++ = (576-312+OPT_SIZE) & 0xff;
#endif	/* CFG_CMD_DHCP */

#if (CONFIG_BOOTP_MASK & CONFIG_BOOTP_SUBNETMASK)
    *e++ =  1;		/* Subnet mask request */
    *e++ =  4;
     e  +=  4;
#endif

#if (CONFIG_BOOTP_MASK & CONFIG_BOOTP_GATEWAY)
    *e++ =  3;		/* Default gateway request */
    *e++ =  4;
     e  +=  4;
#endif

#if (CONFIG_BOOTP_MASK & CONFIG_BOOTP_DNS)
    *e++ =  6;		/* Domain Name Server */
    *e++ =  4;
     e  +=  4;
#endif

#if (CONFIG_BOOTP_MASK & CONFIG_BOOTP_HOSTNAME)
    *e++ = 12;		/* Host name request */
    *e++ = 32;
     e  += 32;
#endif

#if (CONFIG_BOOTP_MASK & CONFIG_BOOTP_BOOTFILESIZE)
    *e++ = 13;		/* Boot file size */
    *e++ =  2;
     e  +=  2;
#endif

#if (CONFIG_BOOTP_MASK & CONFIG_BOOTP_BOOTPATH)
    *e++ = 17;		/* Boot path */
    *e++ = 32;
     e  += 32;
#endif

#if (CONFIG_BOOTP_MASK & CONFIG_BOOTP_NISDOMAIN)
    *e++ = 40;		/* NIS Domain name request */
    *e++ = 32;
     e  += 32;
#endif

    *e++ = 255;		/* End of the list */

    return e - start ;
}
#endif	/* CFG_CMD_DHCP */

void
BootpRequest (void)
{
	volatile uchar *pkt, *iphdr;
	Bootp_t *bp;
	int ext_len, pktlen, iplen;

#if (CONFIG_COMMANDS & CFG_CMD_DHCP)
	dhcp_state = INIT;
#endif

	printf("BOOTP broadcast %d\n", ++BootpTry);
	pkt = NetTxPacket;
	memset ((void*)pkt, 0, PKTSIZE);

	NetSetEther(pkt, NetBcastAddr, PROT_IP);
	pkt += ETHER_HDR_SIZE;

	/*
	 * Next line results in incorrect packet size being transmitted, resulting
	 * in errors in some DHCP servers, reporting missing bytes.  Size must be
	 * set in packet header after extension length has been determined.
	 * C. Hallinan, DS4.COM, Inc.
	 */
	/* NetSetIP(pkt, 0xffffffffL, PORT_BOOTPS, PORT_BOOTPC, sizeof (Bootp_t)); */
	iphdr = pkt;	/* We need this later for NetSetIP() */
	pkt += IP_HDR_SIZE;

	bp = (Bootp_t *)pkt;
	bp->bp_op = OP_BOOTREQUEST;
	bp->bp_htype = HWT_ETHER;
	bp->bp_hlen = HWL_ETHER;
	bp->bp_hops = 0;
	bp->bp_secs = SWAP16( get_timer(0) / CFG_HZ);
	NetWriteIP((vuchar*)&bp->bp_ciaddr, 0);
	NetWriteIP((vuchar*)&bp->bp_yiaddr, 0);
	NetWriteIP((vuchar*)&bp->bp_siaddr, 0);
	NetWriteIP((vuchar*)&bp->bp_giaddr, 0);
	NetCopyEther(bp->bp_chaddr, NetOurEther);
	copy_filename (bp->bp_file, BootFile, sizeof(bp->bp_file));

	/* Request additional information from the BOOTP/DHCP server */
#if (CONFIG_COMMANDS & CFG_CMD_DHCP)
	ext_len = DhcpExtended(bp->bp_vend, DHCP_DISCOVER, 0, 0);
#else
	ext_len = BootpExtended(bp->bp_vend);
#endif	/* CFG_CMD_DHCP */

	/*
	 *	Bootp ID is the lower 4 bytes of our ethernet address
	 *	plus the current time in HZ.
	 */
	BootpID = ((ulong)NetOurEther[2] << 24)
		| ((ulong)NetOurEther[3] << 16)
		| ((ulong)NetOurEther[4] << 8)
		| (ulong)NetOurEther[5];
	BootpID += get_timer(0);
	memcpy(&bp->bp_id, &BootpID, sizeof(bp->bp_id));

	/*
	 * Calculate proper packet lengths taking into account the
	 * variable size of the options field
	 */
	pktlen = BOOTP_SIZE - sizeof(bp->bp_vend) + ext_len;
	iplen = BOOTP_HDR_SIZE - sizeof(bp->bp_vend) + ext_len;
	NetSetIP(iphdr, 0xffffffffL, PORT_BOOTPS, PORT_BOOTPC, iplen);
	NetSetTimeout(SELECT_TIMEOUT * CFG_HZ, BootpTimeout);

#if (CONFIG_COMMANDS & CFG_CMD_DHCP)
	dhcp_state = SELECTING;
	NetSetHandler(DhcpHandler);
#else
	NetSetHandler(BootpHandler);
#endif	/* CFG_CMD_DHCP */
	NetSendPacket(NetTxPacket, pktlen);
}

#if (CONFIG_COMMANDS & CFG_CMD_DHCP)
void DhcpOptionsProcess(char *popt)
{
	char *end = popt + BOOTP_HDR_SIZE;
	int oplen, size;

	while ( popt < end && *popt != 0xff ) {
		oplen = *(popt + 1);
		switch(*popt) {
			case  1:
				NetOurSubnetMask = *(IPaddr_t *)(popt + 2);
				break;
			case  3:
				NetOurGatewayIP = *(IPaddr_t *)(popt + 2);
				break;
			case  6:
				NetOurDNSIP = *(IPaddr_t *)(popt +2);
				break;
			case 12:
				size = truncate_sz ("Host Name",
						    sizeof(NetOurHostName),
						    oplen);
				memcpy(&NetOurHostName, popt+2, size);
				NetOurHostName[size] = 0 ;
				break;
			case 15:		/* Ignore Domain Name Option */
				break;
			case 17:
				size = truncate_sz ("Root Path",
						    sizeof(NetOurRootPath),
						    oplen);
				memcpy(&NetOurRootPath, popt+2, size);
				NetOurRootPath[size] = 0 ;
				break;
			case 51:
				dhcp_leasetime = *(unsigned int *)(popt + 2);
				break;
			case 53:		/* Ignore Message Type Option */
				break;
			case 54:
				NetServerIP = *(IPaddr_t *)(popt+2);
				break;
			case 58:		/* Ignore Renewal Time Option */
				break;
			case 59:		/* Ignore Rebinding Time Option */
				break;
			default:
				printf("*** Unhandled DHCP Option in OFFER/ACK: %d\n",
					*popt);
				break;
		}
		popt += oplen + 2;	/* Process next option */
	}
}

static int DhcpMessageType(unsigned char *popt)
{
	ulong vendmagic;
	memcpy(&vendmagic, popt, 4);
	if (SWAP32(vendmagic) != BOOTP_VENDOR_MAGIC)
		return -1;

	popt += 4;
	while ( *popt != 0xff ) {
		if ( *popt == 53 )	/* DHCP Message Type */
			return *(popt + 2);
		popt += *(popt + 1) + 2;	/* Scan through all options */
	}
	return -1;
}

void DhcpSendRequestPkt(Bootp_t *bp_offer)
{
	volatile uchar *pkt, *iphdr;
	Bootp_t *bp;
	int pktlen, iplen, extlen;

	debug ("DhcpSendRequestPkt: Sending DHCPREQUEST\n");
	pkt = NetTxPacket;
	memset ((void*)pkt, 0, PKTSIZE);

	NetSetEther(pkt, NetBcastAddr, PROT_IP);
	pkt += ETHER_HDR_SIZE;

	iphdr = pkt;		/* We'll need this later to set proper pkt size */
	pkt += IP_HDR_SIZE;

	bp = (Bootp_t *)pkt;
	bp->bp_op = OP_BOOTREQUEST;
	bp->bp_htype = HWT_ETHER;
	bp->bp_hlen = HWL_ETHER;
	bp->bp_hops = 0;
	bp->bp_secs = SWAP16( get_timer(0) / CFG_HZ);
	NetCopyIP((vuchar*)&bp->bp_ciaddr, (vuchar*)&bp_offer->bp_ciaddr);
	NetCopyIP((vuchar*)&bp->bp_yiaddr, (vuchar*)&bp_offer->bp_yiaddr);
	NetCopyIP((vuchar*)&bp->bp_siaddr, (vuchar*)&bp_offer->bp_siaddr);
	NetCopyIP((vuchar*)&bp->bp_giaddr, (vuchar*)&bp_offer->bp_giaddr);
	NetCopyEther(bp->bp_chaddr, NetOurEther);

	/*
	 * ID is the id of the OFFER packet
	 */

	memcpy(bp->bp_id, bp_offer->bp_id, sizeof(bp->bp_id);

	/*
	 * Copy options from OFFER packet if present
	 */
	extlen = DhcpExtended(bp->bp_vend, DHCP_REQUEST, NetServerIP, bp->bp_yiaddr);

	pktlen = BOOTP_SIZE - sizeof(bp->bp_vend) + extlen;
	iplen = BOOTP_HDR_SIZE - sizeof(bp->bp_vend) + extlen;
	NetSetIP(iphdr, 0xffffffffL, PORT_BOOTPS, PORT_BOOTPC, iplen);

	debug ("Transmitting DHCPREQUEST packet: len = %d\n", pktlen);
	NetSendPacket(NetTxPacket, pktlen);
}

/*
 *	Handle DHCP received packets.
 */
static void
DhcpHandler(uchar * pkt, unsigned dest, unsigned src, unsigned len)
{
	Bootp_t *bp = (Bootp_t *)pkt;

	debug ("DHCPHandler: got packet: (src=%d, dst=%d, len=%d) state: %d\n",
		src, dest, len, dhcp_state);

	if (BootpCheckPkt(pkt, dest, src, len))	/* Filter out pkts we don't want */
		return;

	debug ("DHCPHandler: got DHCP packet: (src=%d, dst=%d, len=%d) state: %d\n",
		src, dest, len, dhcp_state);

	switch (dhcp_state) {
	case SELECTING:
		/*
		 * Wait an appropriate time for any potential DHCPOFFER packets
		 * to arrive.  Then select one, and generate DHCPREQUEST response.
		 * If filename is in format we recognize, assume it is a valid
		 * OFFER from a server we want.
		 */
		debug ("DHCP: state=SELECTING bp_file: \"%s\"\n", bp->bp_file);
#ifdef CFG_BOOTFILE_PREFIX
		if (strncmp(bp->bp_file,
			    CFG_BOOTFILE_PREFIX,
			    strlen(CFG_BOOTFILE_PREFIX)) == 0 ) {
#endif	/* CFG_BOOTFILE_PREFIX */

			debug ("TRANSITIONING TO REQUESTING STATE\n");
			dhcp_state = REQUESTING;
#if 0
			if ((*(uint *)bp->bp_vend) == BOOTP_VENDOR_MAGIC)
				DhcpOptionsProcess(&bp->bp_vend[4]);

#endif
			BootpCopyNetParams(bp);	/* Store net params from reply */

			NetSetTimeout(TIMEOUT * CFG_HZ, BootpTimeout);
			DhcpSendRequestPkt(bp);
#ifdef CFG_BOOTFILE_PREFIX
		}
#endif	/* CFG_BOOTFILE_PREFIX */

		return;
		break;
	case REQUESTING:
		debug ("DHCP State: REQUESTING\n");

		if ( DhcpMessageType(bp->bp_vend) == DHCP_ACK ) {
			if ((*(uint *)bp->bp_vend) == BOOTP_VENDOR_MAGIC)
				DhcpOptionsProcess(&bp->bp_vend[4]);
			BootpCopyNetParams(bp);	/* Store net params from reply */
			dhcp_state = BOUND;
			printf("DHCP client bound to address ");
			print_IPaddr(NetOurIP);
			printf("\n");
			/* Send ARP request to get TFTP server ethernet address.
			 * This automagically starts TFTP, too.
			 */
			ArpRequest();
			return;
		}
		break;
	default:
		printf("DHCP: INVALID STATE\n");
		break;
	}

}

void DhcpRequest(void)
{
	BootpRequest();
}
#endif	/* CFG_CMD_DHCP */

#endif /* CFG_CMD_NET */
