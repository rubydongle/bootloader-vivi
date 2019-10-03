/*
 * (C) Copyright 2000
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <armboot.h>
#include <command.h>
#include "net.h"
#include "bootp.h"
#include "tftp.h"
#include "arp.h"

#if (CONFIG_COMMANDS & CFG_CMD_NET)

#define TIMEOUT		5		/* Seconds before trying ARP again */

static void ArpHandler(uchar *pkt, unsigned dest, unsigned src, unsigned len);
static void ArpTimeout(void);

int	ArpTry = 0;

/*
 *	Handle a ARP received packet.
 */
static void
ArpHandler(uchar *pkt, unsigned dest, unsigned src, unsigned len)
{
#ifdef	DEBUG
	printf("Got good ARP - start TFTP\n");
#endif
	TftpStart ();
}


/*
 *	Timeout on ARP request.  Try again, forever.
 */
static void
ArpTimeout(void)
{
	ArpRequest ();
}


void
ArpRequest (void)
{
	int i;
	volatile uchar *pkt;
	ARP_t *	arp;

	printf("ARP broadcast %d\n", ++ArpTry);
	pkt = NetTxPacket;

	NetSetEther(pkt, NetBcastAddr, PROT_ARP);
	pkt += ETHER_HDR_SIZE;

	arp = (ARP_t *)pkt;

	arp->ar_hrd = SWAP16(ARP_ETHER);
	arp->ar_pro = SWAP16(PROT_IP);
	arp->ar_hln = 6;
	arp->ar_pln = 4;
	arp->ar_op  = SWAP16(ARPOP_REQUEST);

	NetCopyEther(&arp->ar_data[0], NetOurEther);	/* source ET addr	*/
	NetWriteIP((uchar*)&arp->ar_data[6], NetOurIP);   /* source IP addr	*/
	for (i=10; i<16; ++i) {
		arp->ar_data[i] = 0;			/* dest ET addr = 0	*/
	}
	NetWriteIP((uchar*)&arp->ar_data[16],		/* dest IP addr		*/
		   NetOurGatewayIP ? NetOurGatewayIP	/* => Gateway		*/
				   : NetServerIP);	/* => TFTP server	*/

	NetSendPacket(NetTxPacket, ETHER_HDR_SIZE + ARP_HDR_SIZE);

	NetSetTimeout(TIMEOUT * CFG_HZ, ArpTimeout);
	NetSetHandler(ArpHandler);
}

#endif /* CFG_CMD_NET */
