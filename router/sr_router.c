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

  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  // Check if length is reasonable.
  if ((sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t)) > len)
  {
    printf("the ip packet length was less than size of ip header plus ethernet header\n");
    return;
  }

  /* validate checksum */
  uint16_t *tempSum = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  if (cksum(ip_header, sizeof(sr_ip_hdr_t)) != tempSum)
  {
    /* TODO checksum error */
    ip_header->ip_sum = tempSum; // Change the wrong sum back
    printf("the ip packet sum was not right.");
    return;
  }
  ip_header->ip_sum = tempSum; // Change the sum back no matter what

  uint32_t dest_ip_n = ip_header->ip_dst;
  uint32_t dest_ip_h = ntohl(ip_header->ip_dst);

  /* Get interface IP address */
  struct sr_if *receiving_interface = sr_get_interface(sr, interface);
  if (receiving_interface->ip == dest_ip_h)
  {
    /* TODO packet is for the router, handle it */
    return;
  }

  /* TODO packet not meant for router, forward it*/

  /* validate TTL */
  if (ip_header->ip_ttl == 0)
  {
    /* TODO TTL error */
    return;
  }

  /* find routing table match */
  struct sr_rt *rt_entry = longest_prefix_match(sr, dest_ip_n);
  if (rt_entry == NULL)
  {
    /* TODO send ICMP host unreachable*/
    return;
  }

  /* TODO check ARP */
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, dest_ip_n);
  if (arp_entry == NULL)
  {
    /* TODO did not find matching ARP MAC address*/
    return;
  }

  /* TODO update eth header and checksum */
  sr_ethernet_hdr_t *packet_as_eth = (sr_ethernet_hdr_t *)packet;

  /* TODO update TTL and checksum */
  sr_ip_hdr_t *packet_as_ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* TODO forward packet */
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

struct sr_rt *longest_prefix_match(struct sr_instance *sr /*lent*/,
                                   uint32_t dest_ip_n /*lent, in network byte order */)
{
  struct sr_rt *table_entry = sr->routing_table;
  struct sr_rt *longest_entry = NULL;
  uint32_t longest_prefix = 0;
  while (table_entry != NULL)
  {
    uint32_t masked = dest_ip_n & table_entry->mask.s_addr;
    if (masked == table_entry->dest.s_addr)
    {
      if (longest_entry == NULL)
      {
        longest_prefix = masked;
        longest_entry = table_entry;
      }
      else if (masked)
      {
        if (masked > longest_prefix)
        {
          longest_prefix = masked;
          longest_entry = table_entry;
        }
      }
    }
    table_entry = table_entry->next;
  }
  return longest_entry;
}
