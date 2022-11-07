# Assigment 3: Simple Router

## Description
This repository is created for assignment 3 project during lecture CSCD58 in 2022F UTSC.  

## Repo
Repository is hosted at [`https://github.com/Lemonsity/SimpleRouter/tree/feature/ping-server`](https://github.com/Lemonsity/SimpleRouter/tree/feature/ping-server). The link would bring you directly to the most up-to-date branch

## Setup
- run `./config.sh`
- go into `router` subdirectory, and run `make` 
- go back to base directory, run `./run_pox.sh` 
- run `./run_mininet.sh` 
- go into `router` subdirectory, and run `./sr`
- go to mininet terminal to see router in action 

## Group Member
| Name | utorId | Student # |
| ---- | ------ | --------- |
| Hongxiao Niu | niuhongx | 1006217345 |
| Lianting Wang | wangl157 | 1007452374 |
| Youzhang Sun | sunyou | 1005982830 |

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
    - Forward packet if packet not for router

3. `void sr_handle_arp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface_name )`
    - Control flow for handling either ARP request or reply

4. `int sr_handle_arp_req()` & `int sr_handle_arp_reply(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface_name /*lent*/)`
    - Finer implementation of handling ARP packets
    - If is reply, then insert ARP into cache, and forward all awaiting packets related to that IP

5. `int sr_handle_ip_packet_forwarding(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface)`
    - Given a packet to be forwarded, decided where and how its forwarded

6. `int send_icmp_unreachable_or_timeout(struct sr_instance* sr, uint8_t* buf, unsigned int len, char* interface, uint8_t icmp_type, uint8_t icmp_code)`
    - Helper function
    - Given the type and code, Send out an ICMP error message

7. `struct sr_if *longest_prefix_match(struct sr_instance *sr, sr_ip_hdr_t *ip_header)`
    - For routing, matching IP with routing table for interface to send to

8. `int send_back_arp_req(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface_name )`
    - Handle ARP request from else where
    - prepare and send reply

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

## Tests

- Route packets through applicatoin servers
    - Demonstrated via `client wget http://192.168.2.2`, `client ping server1`

- Correctly handle ARP request:
    - Demonstrated partially via CL output, and 
    - The ability to route packets, demonstrates correct ARP request and replies must be sent and received properly (Since ARP cache always starts empty)

- Correctly handle traceroute

- Correctly handle ICMP Echo
    - Demonstrated via `client ping server1`

- Reject TCP/UDP via ICMP Port Unreachable

- Maintain ARP cache timeout
    - Handled by starter code

- Queue waiting replies, and send out later
    - Can be demonstrated on the first first `ping`/`traceroute` after starting mininet. Monitoring Wireshark can demonstrate that the router send out ARP requests for destination addresses (since ARP is empty to begin with). `ping` especially shows the correctness, as no `icmp_seq` would be skipped

- ARP request timeout
    - Done via implementation of `sr_arpcache_sweepreqs` function.
    - Can also be seen as when `client ping server1`, on the ~15th ping, the TTL is significantly greater, demonstrating a timeout, and the need to re-request for ARP cache
