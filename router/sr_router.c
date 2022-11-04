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
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

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

void sr_init(struct sr_instance *sr)
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

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */
  /* TODO This function needs to be completed */
  if (len < sizeof(sr_ethernet_hdr_t))
  {
    /* TODO packet too short to be ethernet */
  }
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;

  /* Control flow for different ethernet protocol */
  if (ethernet_header->ether_type == htons(ethertype_ip) && len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
  {
    printf("header type is handle ip packet type");
    sr_handle_ip_packet(sr, packet, len, interface);
  }
  else if (ethernet_header->ether_type == htons(ethertype_arp) && len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
  {
    /* TODO handle ARP sr_handle_arp_packet(sr, packet, len, interface);*/
  }
  else
  {
    /* TODO not ip or arp */
  }
} /* end sr_ForwardPacket */

/*-------------------------------------------------
 * One should make sure that the packet is indeed an IP packet before calling
 *
 *------------------------------------------------*/
void sr_handle_ip_packet(struct sr_instance *sr /*lent*/,
                         uint8_t *packet /*lent*/,
                         unsigned int len,
                         char *interface /*lent*/)
{
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *corresponing_interface = sr_get_interface(sr, interface);

  /* Check if length is reasonable. */
  if ((sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t)) > len)
  {
    printf("the ip packet length was less than size of ip header plus ethernet header\n");
    return;
  }

  /* validate checksum */
  uint16_t tempSum = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  if (cksum(ip_header, sizeof(sr_ip_hdr_t)) != tempSum)
  {
    /* TODO checksum error */
    ip_header->ip_sum = tempSum; /* Change the wrong sum back */
    printf("the ip packet sum was not right.\n");
    return;
  }
  ip_header->ip_sum = tempSum; /* Change the sum back no matter what. */

  /* check what is package destination. */
  struct sr_if *curr_interface = sr->if_list;
  while (curr_interface != NULL)
  {
    /* if the package is belong to my route. */
    if (ip_header->ip_dst == curr_interface->ip)
    {
      printf("this package belong to my route.\n");

      /* Check the packet is icmp packet(Internet Control Message Protocol) */
      if (ip_protocol_icmp == ip_header->ip_p)
      {
        printf("this package is icmp packet\n");

        sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* Check if the packet is Echo reply (type 0) */
        if (icmp_header->icmp_type == 0x08)
        {
          printf("the icmp packet type is echo.\n");

          /* find interface by longest prefix match */
          struct sr_if *temp_interface = longest_prefix_match(sr, ip_header);

          /* Change ethernet header info */
          memcpy(ethernet_header->ether_dhost, ethernet_header->ether_shost, ETHER_ADDR_LEN);
          memcpy(ethernet_header->ether_shost, temp_interface->addr, ETHER_ADDR_LEN);
          /* Change ip header info */
          ip_header->ip_dst = ip_header->ip_src;
          ip_header->ip_src = corresponing_interface->ip;
          ip_header->ip_sum = 0;
          ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
          /* Change icmp header info */
          icmp_header->icmp_code = 0x00;
          icmp_header->icmp_type = 0x00;
          icmp_header->icmp_sum = 0;
          icmp_header->icmp_sum = cksum(icmp_header, ntohs(len) -
                                                         sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

          sr_send_packet(sr, packet, len, temp_interface->name);
        }
        /* Then else, Port unreachable (type 3, code 3) */
        else
        {
          printf("this package is TCP/UDP packet\n");
          /* Base on current teammate function call, MAY need to change arguments */
          send_icmp_unreachable_or_timeout(sr, packet, len, curr_interface, 0x03, 0x03);
        }
        return;
      }
      curr_interface = curr_interface->next;
    }
  }

  /* if this package NOT belong to my route. */
  printf("this package NOT belong to my route.\n");
  /* validate TTL */
  ip_header->ip_ttl -= 1;
  if (ip_header->ip_ttl == 0)
  {
    /* TODO TTL error, Time exceeded (type 11, code 0) */
    printf("ip packet Time exceeded (type 11, code 0)\n");
    send_icmp_unreachable_or_timeout(sr, packet, len, curr_interface, 0x00, 0x11);
    return;
  }
  /* TODO forward packet */
  sr_handle_ip_packet_forwarding(sr, packet, len, curr_interface);
}

void decrement_ttl(sr_ip_hdr_t *ip_header)
{
  ip_header->ip_ttl--;
  /* TODO update checksum*/
}

/*---------------------
 * validate_ip_checksum
 * Given a ip_header, calculate its checksum
 * If the checksum is valid, the function should return 0
 * If return non-zero, it indicated the checksum is not valid
-----------------------*/
/*
uint8_t validate_ip_checksum(sr_ip_hdr_t *ip_header)
{
  uint32_t sum = 0;
  uint16_t *address = ip_header;
  int i = 0;
  for (; i < 10; i++)
  {
    sum += *address;
    address++;
  }
  while (sum >> 16)
  {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return ~sum;
}
*/

struct sr_if *longest_prefix_match(struct sr_instance *sr, sr_ip_hdr_t *ip_header)
{
  struct sr_if *temp_interface = NULL;

  struct sr_rt *curr_table_row = sr->routing_table;
  while (curr_table_row != NULL)
  {
    /* find the longest prefix match */
    uint32_t masked = curr_table_row->mask.s_addr & ip_header->ip_src;
    if (masked == curr_table_row->dest.s_addr)
    {
      temp_interface = sr_get_interface(sr, curr_table_row->interface);
    }
    curr_table_row = curr_table_row->next;
  }
  return temp_interface;
}

void sr_handle_ip_packet_forwarding(struct sr_instance *sr, uint8_t *packet,
                                    unsigned int len, struct sr_if *interface)
{
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;

  struct sr_if *temp_interface = longest_prefix_match(sr, ip_header);

  /* if longest_prefix_match can find one interface to match */
  if (temp_interface != NULL)
  {
    printf("matched with one of table. Check ARP cache.\n");

    struct sr_arpentry *hitted = sr_arpcache_lookup(&sr->cache, ip_header->ip_dst);

    /* hitted cache */
    if (hitted != NULL)
    {
      printf("hitted ARP cache, send packet to next hop\n");
      memcpy(ethernet_header->ether_dhost, hitted->mac, ETHER_ADDR_LEN);
      memcpy(ethernet_header->ether_shost, temp_interface->addr, ETHER_ADDR_LEN);
      ip_header->ip_sum = 0;
      ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
      sr_send_packet(sr, packet, len, temp_interface->name);
      free(hitted);
    }
    /* NOT hitted cache */
    else
    {
      printf("NOT hitted ARP cache, send ARP request\n");
      struct sr_arpreq *request = sr_arpcache_queuereq(&sr->cache, ip_header->ip_dst,
                                                       packet, len, temp_interface->name);
      handle_arpreq(sr, request);
    }
  }
  /* if longest_prefix_match can NOT find one interface to match */
  else
  {
    printf("Did not match with table, Destination net unreachable(type 3,code 0)");
    send_icmp_unreachable_or_timeout(sr, packet, len, interface, 0x00, 0x03);
  }
}