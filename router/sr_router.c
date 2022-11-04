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
#include <stdlib.h>
#include <assert.h>
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

  /* Control flow for different ethernet protocol */
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

/*-------------------------------------------------
 * One should make sure that the packet is indeed an IP packet before calling
 *
 *------------------------------------------------*/
void sr_handle_ip_packet(struct sr_instance* sr /*lent*/,
  uint8_t* packet /*lent*/,
  unsigned int len,
  char* interface /*lent*/) {

  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  /* validate checksum */
  if (validate_ip_checksum(ip_header) != 0) {
    /* TODO checksum error */
    return;
  }

  uint32_t dest_ip_n = ip_header->ip_dst;
  uint32_t dest_ip_h = ntohl(ip_header->ip_dst);

  /* Get interface IP address */
  struct sr_if* receiving_interface = sr_get_interface(sr, interface);
  if (receiving_interface->ip == dest_ip_h) {
    /* TODO packet is for the router, handle it */
    return;
  }

  /* TODO packet not meant for router, forward it*/

  /* validate TTL */
  /* If TTL == 1, then the router would decrement it to 0 and send ICMP*/
  if (ip_header->ip_ttl == 1) {
    /* TODO TTL error, ICMP */

    return;
  }

  /* find routing table match */
  struct sr_rt* rt_entry = longest_prefix_match(sr, dest_ip_n);
  if (rt_entry == NULL) {
    /* TODO send ICMP host unreachable*/
    return;
  }

  /* TODO check ARP */
  struct sr_arpentry* arp_entry = sr_arpcache_lookup(&sr->cache, dest_ip_n);
  if (arp_entry == NULL) {
    /* TODO did not find matching ARP MAC address*/
    return;
  }

  /* TODO update eth header and checksum */
  sr_ethernet_hdr_t* packet_as_eth = (sr_ethernet_hdr_t*)packet;


  /* TODO update TTL and checksum */
  sr_ip_hdr_t* packet_as_ip = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  /* TODO forward packet */


}

void sr_handle_arp_packet(struct sr_instance* sr,
  uint8_t* packet /*lent*/,
  unsigned int len,
  char* interface_name /*lent*/) {

  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t op = ntohs(arp_header->ar_op);
  int result = 0;
  if (op == arp_op_request) {
    result = sr_handle_arp_req(sr, packet, len, interface_name);
  } else if (op == arp_op_reply) {
    result = sr_handle_arp_reply(sr, packet, len, interface_name);
  } else {
    /* TODO unknown arp op */

  }
}

int sr_handle_arp_req(struct sr_instance* sr,
  uint8_t* packet /*lent*/,
  unsigned int len,
  char* interface_name /*lent*/) {
  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if* interface = sr_get_interface(sr, interface_name);
  uint16_t target_ip_h = ntohl(arp_header->ar_tip);
  uint16_t from_ip_h = ntohl(arp_header->ar_sip);

  if (interface->ip != target_ip_h) {
    /* TODO packet not meant for us, maybe just drop it? */
    return 10;
  }

  sr_arpcache_insert(&(sr->cache), arp_header->ar_hrd, from_ip_h);
  struct sr_arpentry* arp_req = sr_arpcache_lookup(&(sr->cache), from_ip_h);
  if (arp_req != NULL) {
    int result = forward_ip_packet_for_arp_req(sr, arp_req, interface_name);
    free(arp_req);
    if (result) {
      return result;
    }
  }
  return 0;
}

int forward_ip_packet_for_arp_req(struct sr_instance* sr,
  struct sr_arpentry* arp_req,
  char* interface_name /*lent*/) {
  /* get packet interface */
  struct sr_if* interface = sr_get_interface(sr, interface_name);

  /* Allocate packet */
  uint8_t* combined_packet = (uint8_t*)calloc(1, ETHER_ADDR_LEN);
  
  /* Divide into blocks */
  sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)combined_packet;
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(combined_packet + sizeof(sr_ethernet_hdr_t));

  /* Copy value */
  memcpy(combined_packet, interface->addr, ETHER_ADDR_LEN);

  memcpy(ethernet_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
  memcpy(ethernet_header->ether_dhost, arp_req->mac, ETHER_ADDR_LEN);

  /*========================================*/
  /* TODO do I handle TTL here? or earlier? */
  /*========================================*/

  int result = sr_send_packet(sr, combined_packet, ETHER_ADDR_LEN, interface->name);
  free(combined_packet);
  if (result) {
    return 2;
  }
  return 0;
}

int sr_handle_arp_reply(struct sr_instance* sr,
  uint8_t* packet /*lent*/,
  unsigned int len,
  char* interface_name /*lent*/) {
  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if* interface = sr_get_interface(sr, interface_name);
  uint16_t target_ip_h = ntohl(arp_header->ar_tip);

  if (interface->ip != target_ip_h) {
    /* TODO packet not meant for us, maybe just drop it? */
    return 10;
  }

  /* TODO arp meant for us*/
  struct sr_arpreq* arp_request = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, target_ip_h);
  if (arp_request != NULL) {
    int result = forward_ip_packet_for_arp_reply(sr, arp_request);
    if (result) {
      return result;
    }
    sr_arpreq_destroy(&(sr->cache), arp_request);
  }
  return 0;
}

int forward_ip_packet_for_arp_reply(struct sr_instance* sr,
  struct sr_arpreq* arp_request) {
  /* get arp entry of the matching ip */
  struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), arp_request->ip);
  if (arp_entry == NULL) {
    /* TODO cache got deleted in the middle, abort abort!!! */
    return 10;
  }
  struct sr_rt* routing_entry = longest_prefix_match(sr, arp_request->ip);
  if (routing_entry == NULL) {
    /* TODO No Routing */
    free(arp_entry);
    return 20;
  }
  struct sr_if* exit_interface = sr_get_interface(sr, routing_entry->interface);
  if (exit_interface == NULL) {
    /* TODO NO exit interface*/
    free(arp_entry);
    return 30;
  }

  struct sr_packet* packet = arp_request->packets;
  while (packet != NULL) {

    /* Allocate for packet */
    uint8_t* combined_packet = (uint8_t*)calloc(1, packet->len);
    if (combined_packet == NULL) {
      free(arp_entry);
      return 1;
    }
    /* Divide into blocks */
    sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)combined_packet;
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(combined_packet + sizeof(sr_ethernet_hdr_t));

    /* Copy value */
    memcpy(combined_packet, packet->buf, packet->len);

    memcpy(ethernet_header->ether_shost, exit_interface->addr, ETHER_ADDR_LEN);
    memcpy(ethernet_header->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

    /*========================================*/
    /* TODO do I handle TTL here? or earlier? */
    /*========================================*/

    int result = sr_send_packet(sr, combined_packet, packet->len, exit_interface->name);

    if (result) {
      free(arp_entry);
      return 2;
    }
    free(combined_packet);
    packet = packet->next;
  }
  free(arp_entry);
  return 0;
}

int send_icmp_unreachable_or_timeout(struct sr_instance* sr,
  uint8_t* buf,
  unsigned int len,
  char* interface,
  uint8_t icmp_type,
  uint8_t icmp_code) {
  sr_ethernet_hdr_t* original_eth_header = (sr_ethernet_hdr_t*)buf;
  sr_ip_hdr_t* original_ip_header = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*)calloc(1, sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)calloc(1, sizeof(sr_ip_hdr_t));
  sr_icmp_t3_hdr_t* icmp_header = (sr_icmp_t3_hdr_t*)calloc(1, sizeof(sr_icmp_t3_hdr_t));

  if (eth_header == NULL || ip_header == NULL || icmp_header == NULL) {
    return 100;
  }

  icmp_header->icmp_type = icmp_type;
  icmp_header->icmp_code = icmp_code;
  icmp_header->icmp_sum = 0;
  icmp_header->unused = 0;
  icmp_header->next_mtu = 0;
  /* Assume 8 bytes of data */
  int real_icmp_data_size = ICMP_DATA_SIZE;
  /* IP actually have less then 8 bytes*/
  if (len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t) < real_icmp_data_size) {
    /* Datagram only contains `real_icmp_data_size` bytes of "non-header" data */
    real_icmp_data_size = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
  }
  uint8_t* blank = (uint8_t*)calloc(1, ICMP_DATA_SIZE);
  /* Copy the non-header data into blank */
  memcpy(blank, buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), real_icmp_data_size);
  memcpy(icmp_header->data, blank, ICMP_DATA_SIZE);
  free(blank);

  uint16_t sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));
  icmp_header->icmp_sum = sum;

  /* Fille IP */
  ip_header->ip_v = original_ip_header->ip_v;
  ip_header->ip_hl = 0x5;
  ip_header->ip_tos = original_ip_header->ip_tos;
  ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
  ip_header->ip_id = original_ip_header->ip_id;
  ip_header->ip_off = 0;
  ip_header->ip_ttl = INIT_TTL;
  ip_header->ip_p = ip_protocol_icmp;
  ip_header->ip_sum = 0;
  ip_header->ip_src = htonl(sr_get_interface(sr, interface)->ip);
  ip_header->ip_dst = original_ip_header->ip_src;
  ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

  /* Fill Ethernet*/
  memcpy(eth_header->ether_dhost, original_eth_header->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_header->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
  eth_header->ether_type = htons(ethertype_ip);

  /* combine back into one */
  uint8_t* combined_packet = calloc(1, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
  memcpy(combined_packet, eth_header, sizeof(sr_ethernet_hdr_t));
  memcpy(combined_packet + sizeof(sr_ethernet_hdr_t), ip_header, sizeof(sr_ip_hdr_t));
  memcpy(combined_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), eth_header, sizeof(sr_icmp_hdr_t));
  free(eth_header);
  free(ip_header);
  free(icmp_header);
  int result = sr_send_packet(sr, combined_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t), interface);
  free(combined_packet);

  return result;
}


void decrement_ttl(sr_ip_hdr_t* ip_header) {
  ip_header->ip_ttl--;
  /* TODO update checksum*/
}

/*---------------------
 * validate_ip_checksum
 * Given a ip_header, calculate its checksum
 * If the checksum is valid, the function should return 0
 * If return non-zero, it indicated the checksum is not valid
-----------------------*/
uint8_t validate_ip_checksum(sr_ip_hdr_t* ip_header) {
  uint32_t sum = 0;
  uint16_t* address = ip_header;
  int i = 0;
  for (; i < 10; i++) {
    sum += *address;
    address++;
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return ~sum;
}

struct sr_rt* longest_prefix_match(struct sr_instance* sr /*lent*/,
  uint32_t dest_ip_n /*lent, in network byte order */) {
  struct sr_rt* table_entry = sr->routing_table;
  struct sr_rt* longest_entry = NULL;
  uint32_t longest_prefix = 0;
  while (table_entry != NULL) {
    uint32_t masked = dest_ip_n & table_entry->mask.s_addr;
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
