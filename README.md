# Assigment 3: Simple Router

## Description
This repository is created for assignment 3 project during lecture CSCD58 in 2022F UTSC.  

## Group Member
| Name | utorId | Student # |
| ---- | ------ | --------- |
| Hongxiao Niu | niuhongx | 1006217345 |
| Lianting Wang | wangl157 | 1007452374 |

## Explicit details of the contributions from each member of the team
Hongxiao Niu: 
 - Major contribute about implementing ip package code(`sr_handle_ip_packet(sr, packet, len, interface)`)
 - Control flow logic in the function `sr_handlepacket` 
 - Command line output
 - README.md file
Lianting Wang: 
 - Major contribute about implementing handling arp package code 
 - Extensive QA, including code compatibility, debug
Youzhang Sun: 
 - Major contribute about implementing handle arp package and arp cache code(sr_handle_arp_packet(sr, packet, len, interface))
 - Scaffolding part of `handlepacket`'s control flow 

## Description and documentation for the functions that implemented the required and missed functionalities in the starter code

### sr_router.c
1. `void sr_handlepacket(struct sr_instance *sr, uint8_t *packet , unsigned int len, char *interface)`
    - the marjor function implemented, entry point to handling incoming packets
    - Sanity check packet length
    - Direct data to next step depending on type of network
2. `void sr_handle_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface )`
    - validate `checksum`
    - Determine intended destination of the packet
    - Handle ICMP and TCP/UDP if for router
    - Decrement and check TTL
    - Forward packet ????????????????????????????????????????????????

3. `void sr_handle_arp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface_name )`
    - Control flow for handling either ARP request or reply

4. `int sr_handle_arp_req()` & `int sr_handle_arp_reply(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface_name /*lent*/)`
    - Finer implementation of handling ARP packets
    - If is reply, then insert ARP into cache, and forward all awaiting packets related to that IP

5. `int forward_ip_packet(struct sr_instance* sr, struct sr_arpreq* arp_request)`
    - Given an ARP request, representating the IP packets waiting on the particular ARP request, forward if the matching cache can be found
    - (Designed to be called on receiving an ARP reply)

6. `int send_icmp_unreachable_or_timeout(struct sr_instance* sr, uint8_t* buf, unsigned int len, char* interface, uint8_t icmp_type, uint8_t icmp_code)`
    - Helper function
    - Given the type and code, Send out an ICMP error message

7. `struct sr_if *longest_prefix_match(struct sr_instance *sr, sr_ip_hdr_t *ip_header)`
    - FOr routing, matching IP with routing table for interface to send to

### sr_arpcache.c
1. `void sr_arpcache_sweepreqs(struct sr_instance *sr)`
    - Called every second by router
    - Go through all awaiting requests, call function to handle them

2. `void handle_arpreq(struct sr_instance* sr, struct sr_arpreq * req)`
    - Given a request
    - Send out unreachable error if already sent out 5ARP requests
    - If has not sent out 5 request, and it has been 1 second since last request, make another ARP request

3. `int sr_send_arp_request(struct sr_instance * sr, char * interface_name, uint32_t target_ip)`
    - Broadcast an ARP request for the IP given to the interface given
