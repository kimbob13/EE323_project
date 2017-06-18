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
	
	/* print_hdr_ip((uint8_t *)ip_hdr); */

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

	if(sr_decrement_checksum(ip_hdr) < 0)
	{
		/* Error in decremeting ttl */
	}
	
	/* print_hdr_ip((uint8_t *)ip_hdr); */
	switch(ip_hdr->ip_p)
	{
		case 1:
		{
			/* This IP datagram contains ICMP header. */
			sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ip_hdr + 1);
			/* print_hdr_icmp((uint8_t *)icmp_hdr); */
			if(icmp_hdr->icmp_type == 8)
			{
				/* This is ICMP echo request */
				/* Check whether target IP is in the router's interface list */
				struct sr_if *cur_if = sr->if_list;
				for(; cur_if != NULL; cur_if = cur_if->next)
				{
					if(ntohl(ip_hdr->ip_dst) == ntohl(cur_if->ip))
					{
						/* This ICMP reqeust is for this router */
						break;
					}
				}

				if(cur_if == NULL)
				{
					/* This ICMP echo reqeust should be just forwarded */
					struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
					if(arp_entry == NULL)
					{
						/* This IP address is not in the cache.
						 * Send ARP request. */

						/* print_hdr_ip((uint8_t *)ip_hdr); */

						/* First, find proper output interface */
						struct sr_if *output_if = sr_find_if_by_ip(sr, ip_hdr->ip_dst);
						struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet, len, output_if->name);
						sr_handle_arpreq(sr, req, ip_hdr, output_if);
					}
					else
					{
						printf("ARP cache HIT!\n");
					}
				}
				else
				{
					/* This router should send ICMP echo reply */
				}
			}
		}
	}

	return 0;
}

/* Handle received ARP packet */
int sr_handle_arp(struct sr_instance *sr,
		uint8_t *packet,
		unsigned int len,
		char *interface)
{
	sr_ethernet_hdr_t *eth_frame = (sr_ethernet_hdr_t *)packet;
	sr_arp_hdr_t *arp_recv= (sr_arp_hdr_t *)(eth_frame + 1);

	print_hdr_eth((uint8_t *)eth_frame);
	print_hdr_arp((uint8_t *)arp_recv);

	/* Check whether target IP is in the router's interface list */
	struct sr_if *cur_if = sr->if_list;
	for(; cur_if != NULL; cur_if = cur_if->next)
	{
		if(ntohl(arp_recv->ar_tip) == ntohl(cur_if->ip))
		{
			/* This is valid ARP request */
			break;
		}
	}

	if(cur_if == NULL)
	{
		/* This received ARP packet doesn't target to router */
		fprintf(stderr, "Not a valid packet: received ARP packet doesn't target to router\n");
		return -1;
	}

	switch(ntohs(arp_recv->ar_op))
	{
		case 1:
		{
			printf("sr_router.c - 230: receive ARP request packet.\n");
			/* This is an ARP request packet.
			 * We have to send ARP reply packet */
			uint8_t *arp_send_eth = malloc(sizeof(sr_ethernet_hdr_t));
			/* Destination MAC address is requester's MAC address */
			memcpy(((sr_ethernet_hdr_t *)arp_send_eth)->ether_dhost,
					eth_frame->ether_shost,
					sizeof(uint8_t) * ETHER_ADDR_LEN);
			/* Source MAC address is router's MAC address */
			memcpy(((sr_ethernet_hdr_t *)arp_send_eth)->ether_shost,
					cur_if->addr,
					sizeof(uint8_t) * ETHER_ADDR_LEN);
			/* This ARP reply's ethernet frame type is arp */
			((sr_ethernet_hdr_t *)arp_send_eth)->ether_type =
				htons(ethertype_arp);

			uint8_t *arp_send_arp = malloc(sizeof(sr_arp_hdr_t));
			((sr_arp_hdr_t *)arp_send_arp)->ar_hrd = arp_recv->ar_hrd;
			((sr_arp_hdr_t *)arp_send_arp)->ar_pro = arp_recv->ar_pro;
			((sr_arp_hdr_t *)arp_send_arp)->ar_hln = arp_recv->ar_hln;
			((sr_arp_hdr_t *)arp_send_arp)->ar_pln = arp_recv->ar_pln;
			((sr_arp_hdr_t *)arp_send_arp)->ar_op = htons(arp_op_reply);
			memcpy(((sr_arp_hdr_t *)arp_send_arp)->ar_sha,
					cur_if->addr,
					sizeof(uint8_t) * ETHER_ADDR_LEN);
			((sr_arp_hdr_t *)arp_send_arp)->ar_sip = arp_recv->ar_tip;
			memcpy(((sr_arp_hdr_t *)arp_send_arp)->ar_tha,
					arp_recv->ar_sha,
					sizeof(uint8_t) * ETHER_ADDR_LEN);
			((sr_arp_hdr_t *)arp_send_arp)->ar_tip = arp_recv->ar_sip;

			uint8_t *arp_send = malloc(sizeof(sr_ethernet_hdr_t) +
				sizeof(sr_arp_hdr_t));
			memcpy(arp_send, arp_send_eth, sizeof(sr_ethernet_hdr_t));
			memcpy(arp_send + sizeof(sr_ethernet_hdr_t),
					arp_send_arp, sizeof(sr_arp_hdr_t));
			free(arp_send_eth);
			free(arp_send_arp);
			unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
			/* print_hdr_arp((uint8_t *)(arp_reply + sizeof(sr_ethernet_hdr_t))); */
			if(sr_send_packet(sr, arp_send, len, (const char *)cur_if->name) < 0)
			{
				fprintf(stderr, "Send fail.\n");
				/* return -1; */
				exit(EXIT_FAILURE);
			}
			break;
		}
		case 2:
		{
			/* This is an ARP reply packet */
			
			printf("sr_router.c - 282: receive ARP reply packet.\n");
			print_hdr_arp((uint8_t *)arp_recv);
			break;
		}
		default:
			break;
	}

	return 0;
}

int sr_handle_arpreq(struct sr_instance *sr,
		struct sr_arpreq *req,
		sr_ip_hdr_t *ip_hdr,
		struct sr_if *output_if)
{
	time_t curtime = time(NULL);

	if(difftime(curtime, req->sent) > 1.0)
	{
		/* This request doesn't give any reply */
		if(req->times_sent >= 5)
		{
			/* This request was sent 5 times.
			 * Host is unreachable */
			printf("sr_router.c - 307\n");
			printf("Host is unreachable\n");
		}
		else
		{
			uint8_t broadcast_mac[ETHER_ADDR_LEN];
			uint8_t broadcast_mac_arp[ETHER_ADDR_LEN];
			int pos = 0;
			for(; pos < ETHER_ADDR_LEN; pos++)
			{
				broadcast_mac[pos] = 0xff;
				broadcast_mac_arp[pos] = 0x00;
			}
			uint8_t *arp_req_eth = malloc(sizeof(sr_ethernet_hdr_t));
			memcpy(((sr_ethernet_hdr_t *)arp_req_eth)->ether_dhost,
					broadcast_mac,
					sizeof(uint8_t) * ETHER_ADDR_LEN);
			memcpy(((sr_ethernet_hdr_t *)arp_req_eth)->ether_shost,
					output_if->addr,
					sizeof(uint8_t) * ETHER_ADDR_LEN);
			((sr_ethernet_hdr_t *)arp_req_eth)->ether_type =
				htons(ethertype_arp);

			uint8_t *arp_req_arp = malloc(sizeof(sr_arp_hdr_t));
			((sr_arp_hdr_t *)arp_req_arp)->ar_hrd = htons(arp_hrd_ethernet);
			((sr_arp_hdr_t *)arp_req_arp)->ar_pro = htons(0x800);
			((sr_arp_hdr_t *)arp_req_arp)->ar_hln = ETHER_ADDR_LEN;
			((sr_arp_hdr_t *)arp_req_arp)->ar_pln = ip_hdr->ip_hl;
			((sr_arp_hdr_t *)arp_req_arp)->ar_op = htons(arp_op_request);
			memcpy(((sr_arp_hdr_t *)arp_req_arp)->ar_sha,
					output_if->addr,
					sizeof(uint8_t) * ETHER_ADDR_LEN);
			((sr_arp_hdr_t *)arp_req_arp)->ar_sip = output_if->ip;
			memcpy(((sr_arp_hdr_t *)arp_req_arp)->ar_tha,
					broadcast_mac_arp,
					sizeof(uint8_t) * ETHER_ADDR_LEN);
			((sr_arp_hdr_t *)arp_req_arp)->ar_tip = ip_hdr->ip_dst;

			unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t) + 2;
			uint8_t *arp_req_from_sr = malloc(len);
			memcpy(arp_req_from_sr, arp_req_eth, sizeof(sr_ethernet_hdr_t));
			memcpy(arp_req_from_sr + sizeof(sr_ethernet_hdr_t), arp_req_arp, sizeof(sr_arp_hdr_t));
			/* Save created ARP request to the ARP cache */
			free(arp_req_eth);
			free(arp_req_arp);

			printf("sr_router.c - 351\n");
			print_hdr_eth((uint8_t *)arp_req_from_sr);
			print_hdr_arp((uint8_t *)(arp_req_from_sr + sizeof(sr_ethernet_hdr_t)));

			req->sent = curtime;
			req->times_sent++;
			if(sr_send_packet(sr, arp_req_from_sr, len, (const char *)output_if->name) < 0)
			{
				fprintf(stderr, "Send fail - ARP request from sr.\n");
				return -1;
			}
		}
	}
	else
	{
		printf("sr_router.c - 365\n");
		printf("Wait!\n");
	}
	
	return 0;
}

int sr_decrement_checksum(sr_ip_hdr_t *ip_hdr)
{
	/*
	printf("IP header before decrementing ttl\n");
	print_hdr_ip((uint8_t *)ip_hdr);
	*/

	ip_hdr->ip_ttl -= 1;
	ip_hdr->ip_sum = 0x0000;
	uint16_t new_checksum = cksum((const void *)ip_hdr, sizeof(sr_ip_hdr_t));
	ip_hdr->ip_sum = new_checksum;

	/*
	printf("IP header after decrementing ttl\n");
	print_hdr_ip((uint8_t *)ip_hdr);
	*/

	if(cksum((const void *)ip_hdr, sizeof(sr_ip_hdr_t)) != 0xffff)
	{
		fprintf(stderr, "Error in new checksum value!\n");
		return -1;
	}
	else
	{
		return 0;
	}
}

struct sr_if *sr_find_if_by_ip(struct sr_instance *sr, uint32_t ip)
{
	char *match_node;
	struct sr_if *match_if;
	struct sr_rt *cur_rt_node = sr->routing_table;

	for(; cur_rt_node != NULL; cur_rt_node = cur_rt_node->next)
	{
		if(ip == cur_rt_node->dest.s_addr)
		{
			match_node = strdup(cur_rt_node->interface);
			break;
		}
	}
	match_if = sr_get_interface(sr, (const char *)match_node);

	return match_if;
}
