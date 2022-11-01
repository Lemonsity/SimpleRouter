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

void sr_init(struct sr_instance* sr) {
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
  uint8_t* packet/* lent */,
  unsigned int len,
  char* interface/* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */
  /* TODO This function needs to be completed */
  if (len < sizeof(sr_ethernet_hdr_t)) {
    /* TODO packet too short to be ethernet */
  }
  sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)packet;
  if (ethernet_header->ether_type == htons(ethertype_ip)
    && len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    sr_handle_ip_packet(sr, packet, len, interface);
  } else if (ethernet_header->ether_type == htons(ethertype_arp)
    && len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    sr_handle_arp_packet(sr, packet, len, interface);
  } else {
    /* TODO not ip or arp */
  }
}/* end sr_ForwardPacket */

void sr_handle_ip_packet(struct sr_instance* sr /*lent*/, 
  uint8_t* packet /*lent*/, 
  unsigned int len, 
  char* interface /*lent*/) {

  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  
  /* TODO do checksum here*/
  if (validate_ip_checksum(ip_header) != 0) {
    /* TODO checksum error */
    return;
  }
  /* TODO replace vvv this with getting own IP address*/
  struct sr_if* if_router = sr_get_interface(sr, interface);
  uint16_t router_ip = if_router->ip;
  
  if (router_ip == ip_header->ip_dst) { /* TODO this needs testing, do we need to htonl / ntohl? */
    /* TODO packet meant for router, handle it*/
  } else {
    /* TODO packet not meant for router, forward it*/
    
    uint32_t dest_ip = ip_header->ip_dst;



    /* TODO check routing table*/
    struct sr_rt * rt_entry = longest_prefix_match(sr, dest_ip);
    if (rt_entry == NULL) {
      /* TODO send ICMP host unreachable*/
      return;
    } else {

    }
  }
}

void decrement_ttl(sr_ip_hdr_t * ip_header) {
  ip_header -> ip_ttl--;
  /* TODO update checksum*/
}

/*---------------------
 * validate_ip_checksum
 * Given a ip_header, calculate its checksum
 * If the checksum is valid, the function should return 0
 * If return non-zero, it indicated the checksum is not valid
-----------------------*/
uint8_t validate_ip_checksum(sr_ip_hdr_t * ip_header) {
  uint32_t sum = 0;
  uint16_t * address = ip_header;
  for (int i = 0; i < 10; i++) {
    sum += *address;
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return ~sum;
}



struct sr_rt * longest_prefix_match(struct sr_instance * sr /*lent*/, uint32_t dest_ip /*lent*/) {
  struct sr_rt * table_entry = sr->routing_table;
  struct sr_rt * longest_entry = NULL;
  uint32_t longest_prefix = 0;
  while (table_entry != NULL) {
    uint32_t masked = dest_ip & table_entry->mask.s_addr;
    if (masked == table_entry->dest.s_addr) {
      if (longest_entry == NULL) {
        longest_prefix = masked;
        longest_entry = table_entry;
      } else if (masked) {
        if (masked > longest_prefix) {
          longest_prefix = masked;
          longest_entry = table_entry;
        }
      }
    }
    table_entry = table_entry->next;
  }
  return longest_entry;
}
