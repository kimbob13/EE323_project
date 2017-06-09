/**********************************************************************
* file:  sr_router.c
* date:  Mon Feb 18 12:50:42 PST 2002
* Contact: casado@stanford.edu
*
* Description:
*
* This file contains all the functions that interact directly
* with the routing table, as well as the main entry method
* for routing.
*
**********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
* Method: sr_init(void)
* Scope:  Global
*
* Initialize the routing subsystem
*
*---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
	/* REQUIRES */
	assert(sr);

	/* Initialize cache and cache cleanup thread */
	sr_arpcache_init(&(sr->cache));

	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

	/* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
* Method: sr_handlepacket(uint8_t* p,char* interface)
* Scope:  Global
*
* This method is called each time the router receives a packet on the
* interface.  The packet buffer, the packet length and the receiving
* interface are passed in as parameters. The packet is complete with
* ethernet headers.
*
* Note: Both the packet buffer and the character's memory are handled
* by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
* packet instead if you intend to keep it around beyond the scope of
* the method call.
*
*---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
	uint8_t * packet/* lent */,
	unsigned int len,
	char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n",len);

	size_t minlength = sizeof(sr_ethernet_hdr_t);
	if(len < minlength)
	{
		fprintf(stderr, "Not a valid packet: invalid length.\n");
		return;
	}

	uint16_t eth_type = ethertype(packet);

	if(eth_type == ethertype_ip)
	{
		/* This frame contains IP datagram */
		int result = sr_handle_ip(sr, packet, len, interface);
		if(result < 0)
		{
			/* This ethernet frame doesn't contain valid IP datagram */
		}
	}
	else if(eth_type == ethertype_arp)
	{
		/* This frame contains ARP packet */ 
		int result = sr_handle_arp(sr, packet, len, interface);
		if(result < 0)
		{
			/* This ether net frame doesn't contain valid ARP packet */
		}
	}
	/* fill in code here */

}/* end sr_ForwardPacket */

/* Handle IP datagram */
int sr_handle_ip(struct sr_instance *sr,
		uint8_t *packet,
		unsigned int len,
		char *interface)
{
	sr_ethernet_hdr_t *eth_frame = (sr_ethernet_hdr_t *)packet;
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(eth_frame + 1);
	
	print_hdr_ip((uint8_t *)ip_hdr);
	uint16_t ip_checksum = cksum((const void *)ip_hdr, sizeof(sr_ip_hdr_t));
	if(cksum((const void *)ip_hdr, sizeof(sr_ip_hdr_t)) != 0xffff)
	{
		/* Invalid checksum */
		fprintf(stderr, "Not a valid packet: invalid ip checksum.\n");
		return -1;
	}
	if(len < sizeof(sr_ip_hdr_t))
	{
		/* This datagram does not have valid length */
		fprintf(stderr, "Not a valid packet: invalid ip datagram length.\n");
		return -1;
	}

	return 0;
}

/* Handle ARP request packet */
int sr_handle_arp(struct sr_instance *sr,
		uint8_t *packet,
		unsigned int len,
		char *interface)
{
	sr_ethernet_hdr_t *eth_frame = (sr_ethernet_hdr_t *)packet;
	sr_arp_hdr_t *arp_req= (sr_arp_hdr_t *)(eth_frame + 1);

	/* print_hdr_eth((uint8_t *)eth_frame); */
	/* print_hdr_arp((uint8_t *)arp_req); */

	/* Check whether target IP is in the router's interface list */
	struct sr_if *cur_if = sr->if_list;
	for(; cur_if != NULL; cur_if = cur_if->next)
	{
		if(ntohl(arp_req->ar_tip) == ntohl(cur_if->ip))
		{
			/* This is valid ARP request */
			break;
		}
	}

	if(cur_if == NULL)
	{
		/* This ARP request packet doesn't target to router */
		fprintf(stderr, "Not a valid packet: request doesn't target to router\n");
		return -1;
	}

	switch(ntohs(arp_req->ar_op))
	{
		case 1:
		{
			/* This is an ARP request packet.
			 * We have to send ARP reply packet */
			uint8_t *arp_reply_eth = malloc(sizeof(sr_ethernet_hdr_t));
			/* Destination MAC address is requester's MAC address */
			memcpy(((sr_ethernet_hdr_t *)arp_reply_eth)->ether_dhost,
					eth_frame->ether_shost,
					sizeof(uint8_t) * ETHER_ADDR_LEN);
			/* Source MAC address is router's MAC address */
			memcpy(((sr_ethernet_hdr_t *)arp_reply_eth)->ether_shost,
					cur_if->addr,
					sizeof(uint8_t) * ETHER_ADDR_LEN);
			/* This ARP reply's ethernet frame type is arp */
			((sr_ethernet_hdr_t *)arp_reply_eth)->ether_type =
				htons(ethertype_arp);

			uint8_t *arp_reply_arp = malloc(sizeof(sr_arp_hdr_t));
			((sr_arp_hdr_t *)arp_reply_arp)->ar_hrd = arp_req->ar_hrd;
			((sr_arp_hdr_t *)arp_reply_arp)->ar_pro = arp_req->ar_pro;
			((sr_arp_hdr_t *)arp_reply_arp)->ar_hln = arp_req->ar_hln;
			((sr_arp_hdr_t *)arp_reply_arp)->ar_pln = arp_req->ar_pln;
			((sr_arp_hdr_t *)arp_reply_arp)->ar_op = htons(arp_op_reply);
			memcpy(((sr_arp_hdr_t *)arp_reply_arp)->ar_sha,
					cur_if->addr,
					sizeof(uint8_t) * ETHER_ADDR_LEN);
			((sr_arp_hdr_t *)arp_reply_arp)->ar_sip = arp_req->ar_tip;
			memcpy(((sr_arp_hdr_t *)arp_reply_arp)->ar_tha,
					arp_req->ar_sha,
					sizeof(uint8_t) * ETHER_ADDR_LEN);
			((sr_arp_hdr_t *)arp_reply_arp)->ar_tip = arp_req->ar_sip;

			uint8_t *arp_reply = malloc(sizeof(sr_ethernet_hdr_t) +
				sizeof(sr_arp_hdr_t));
			memcpy(arp_reply, arp_reply_eth, sizeof(sr_ethernet_hdr_t));
			memcpy(arp_reply + sizeof(sr_ethernet_hdr_t),
					arp_reply_arp, sizeof(sr_arp_hdr_t));
			free(arp_reply_eth);
			free(arp_reply_arp);
			unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
			if(!sr_send_packet(sr, arp_reply, len, (const char *)cur_if->name))
			{
				fprintf(stderr, "Send fail.\n");
				return -1;
			}
			break;
		}
		case 2:
		{
			/* This is an ARP reply packet */
			break;
		}
		default:
			break;
	}

	return 0;
}
