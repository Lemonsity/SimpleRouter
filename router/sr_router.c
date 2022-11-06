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

  /* Reminder when receiving packages. */
  printf("*** -> Received packet of length %d \n", len);

  /* Don't waste my time ... */
  if (len < sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr , "** Error: packet is wayy to short \n");
      return;
  }

  /* Control flow for different ethernet protocol */
  if (ethertype(packet) == ethertype_ip
    && len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    printf("This is an IP packet\n");
    sr_handle_ip_packet(sr, packet, len, interface);
  } else if (ethertype(packet) == ethertype_arp
    && len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    printf("This is an ARP packet\n");
    sr_handle_arp_packet(sr, packet, len, interface);
  } else {
    Debug("Unknown ethernet type %d. \n", ethertype(packet));
  }
}

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
          struct sr_if *temp_interface = longest_prefix_match(sr, ip_header->ip_src);

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
          send_icmp_unreachable_or_timeout(sr, packet, len, curr_interface->name, 0x03, 0x03);
        }
        return;
      }
    }
    curr_interface = curr_interface->next;
  }

  /* if this package NOT belong to my route. */
  printf("this package NOT belong to my route.\n");
  /* validate TTL */
  ip_header->ip_ttl -= 1;
  if (ip_header->ip_ttl == 0)
  {
    /* TODO TTL error, Time exceeded (type 11, code 0) */
    printf("ip packet Time exceeded (type 11, code 0)\n");
    send_icmp_unreachable_or_timeout(sr, packet, len, curr_interface->name, 0x00, 0x11);
    return;
  }
  /* TODO forward packet */
  sr_handle_ip_packet_forwarding(sr, packet, len, curr_interface);
}

void sr_handle_arp_packet(struct sr_instance* sr,
  uint8_t* packet /*lent*/,
  unsigned int len,
  char* interface_name /*lent*/) {
  /* Get arp header and opcode. */
  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t op = ntohs(arp_header->ar_op);
  if (op == arp_op_request) {
    int result = sr_handle_arp_req(sr, packet, len, interface_name);
    Debug("sr_handle_arp_req result is %d. \n", result);
  } else if (op == arp_op_reply) {
    int result = sr_handle_arp_reply(sr, packet, len, interface_name);
    Debug("sr_handle_arp_reply result is %d. \n", result);
  } else {
    Debug("Unknown arp op %d. \n", op);
  }
}

int sr_handle_arp_req(struct sr_instance* sr,
  uint8_t* packet /*lent*/,
  unsigned int len,
  char* interface_name /*lent*/) {
  /* Get arp header and packet interface. */
  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if* interface = sr_get_interface(sr, interface_name);

  /* Get target, source and interface ip. */
  uint32_t target_ip_h = arp_header->ar_tip;
  uint32_t source_ip_h = arp_header->ar_sip;
  uint32_t interface_ip_h = interface->ip;

  /* Drop packet if not for us. */
  if (interface_ip_h != target_ip_h) {
    return 10;
  }

  /* Add new arp record in arp cache entry. */
  sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, source_ip_h);
  struct sr_arpentry* arp_req = sr_arpcache_lookup(&(sr->cache), source_ip_h);

  /* If added success, send arp require packet. */
  if (arp_req != NULL) {
    int result = send_back_arp_req(sr, packet, len, interface_name);
    free(arp_req);
    if (result) {
      return result;
    }
  }
  return 0;
}

int send_back_arp_req(struct sr_instance* sr,
  uint8_t* packet /*lent*/,
  unsigned int len,
  char* interface_name /*lent*/) {
  /* Get arp header and packet interface */
  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if* interface = sr_get_interface(sr, interface_name);

  /* Create Ethernet and ARP packet */
  sr_ethernet_hdr_t* ethernet_header;
  sr_arp_hdr_t* arp_packet = (sr_arp_hdr_t*)malloc(sizeof(sr_arp_hdr_t));
  unsigned int total_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  ethernet_header = (sr_ethernet_hdr_t *)malloc(total_len);

  /* Copy ARP value */
  arp_packet->ar_hrd = ntohs(arp_hrd_ethernet);
  arp_packet->ar_pro = ntohs(ethertype_ip);
  arp_packet->ar_hln = ETHER_ADDR_LEN;
  arp_packet->ar_pln = 0x04;
  arp_packet->ar_op = ntohs(arp_op_reply);
  memcpy(arp_packet->ar_sha, interface->addr, ETHER_ADDR_LEN);
  arp_packet->ar_sip = interface->ip;
  memcpy(arp_packet->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
  arp_packet->ar_tip = arp_header->ar_sip;

  /* Copy Ethernet value */
  memcpy(ethernet_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
  memcpy(ethernet_header->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);
  ethernet_header->ether_type = ntohs(ethertype_arp);
  memcpy(((uint8_t*)ethernet_header) + sizeof(sr_ethernet_hdr_t),
    (uint8_t*)arp_packet, sizeof(sr_arp_hdr_t));

  /* Send arp req packet and return the result. */
  int result = sr_send_packet(sr, (uint8_t*)ethernet_header, total_len, interface->name);
  free(arp_packet);
  free(ethernet_header);
  if (result) {
    return 2;
  }
  return 0;
}

int sr_handle_arp_reply(struct sr_instance* sr,
  uint8_t* packet /*lent*/,
  unsigned int len,
  char* interface_name /*lent*/) {
  /* Get arp header and packet interface. */
  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if* interface = sr_get_interface(sr, interface_name);

  /* Get target, source and interface ip. */
  uint32_t target_ip_h = arp_header->ar_tip;
  uint32_t source_ip_h = arp_header->ar_sip;
  uint32_t interface_ip_h = interface->ip;

  /* Drop packet if not for us. */
  if (interface_ip_h != target_ip_h) {
    return 10;
  }

  /* Add new arp record in arp cache entry. */
  struct sr_arpreq* arp_request = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, source_ip_h);
  if (arp_request == NULL) {
    Debug("No packet was waiting on this ARP\n");
    return 0;
  }
  struct sr_arpentry * arp_entry = sr_arpcache_lookup(&(sr->cache), source_ip_h);
  if (arp_entry == NULL) {
    Debug("Error inserting, possibly bad\nAborting forwarding\n");
    free(arp_request);
    return 1;
  }
  Debug("Arp record added success.\n");

  Debug("Forwarding pending packets\n");
  forward_ip_packet(sr, arp_request, arp_entry);
  free(arp_request);
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

struct sr_if *longest_prefix_match(struct sr_instance *sr, uint32_t ip)
{
  struct sr_if *temp_interface = NULL;

  struct sr_rt *curr_table_row = sr->routing_table;
  while (curr_table_row != NULL)
  {
    /* find the longest prefix match */
    uint32_t masked = curr_table_row->mask.s_addr & ip;
    if (masked == curr_table_row->dest.s_addr)
    {
      temp_interface = sr_get_interface(sr, curr_table_row->interface);
    }
    curr_table_row = curr_table_row->next;
  }
  if (temp_interface == NULL) {
    temp_interface = sr->if_list;
  }
  return temp_interface;
}

void sr_handle_ip_packet_forwarding(struct sr_instance *sr, uint8_t *packet,
                                    unsigned int len, struct sr_if *interface)
{
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;

  struct sr_if *temp_interface = longest_prefix_match(sr, ip_header->ip_dst);

  /* if longest_prefix_match can find one interface to match */
  if (temp_interface != NULL)
  {
    printf("matched with one of table. Check ARP cache.\n");

    struct sr_arpentry *hitted = sr_arpcache_lookup(&(sr->cache), ip_header->ip_dst);

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
      sr_arpcache_queuereq(&(sr->cache), ip_header->ip_dst,
        packet, len, temp_interface->name);
    }
  }
  /* if longest_prefix_match can NOT find one interface to match */
  else
  {
    printf("Did not match with table, Destination net unreachable(type 3,code 0) \n");
    send_icmp_unreachable_or_timeout(sr, packet, len, interface->name, 0x00, 0x03);
  }
}
