Student: Maciuca Alexandru Petru
Group: 324CA
Homework: ROUTER
Course: Communication Protocols Course

## About the code

    The homework follows all the steps that a router has to make in order to
    transport a packet from Host X to Host Y. It has to both send and receive
    ARP Requests, ARP Replies and IPV4 packets.

    I have implemented all functions apart from a efficient binary search,
    that is instead changed with a liniar search

## The implementation

    The router has to allocate memory for its RouteTable and 
    for the ARP Cache Table.
    Additionally the router allocates memory for a queue structure used to
    hold multiple packets and for an array that helps in traversing the queue.

    In order to parse the RouteTable, I have used route_table_entry struct.
    Furthermore, the ArpCache Table is dynamically parsed meaning that
    whenever a new connection is made, the table updates itself.  

    The entire process happens in a while loop.

## How it works

    First step is to extract the ethernet header from the package.
    This header will indicate if the following header is a ARP header
    or a IPV4 header.

  * Receiving an ARP Request
    Check if the packet is for the router otherwise drop it.
    If the packet is for the router, send back an ARP Reply,
    building all the necessary headers and use the SEND ARP function.

  * Receiving an ARP Reply
    Update the cache for the router.
    Traverse all packets from the packet_queue and see which packets should
    be transfered to the entity that sent the reply.
    If the packet next hop is similar to the source ip of the reply
    then send the packet, otherwise it has to be inserted back in the queue
    using an extra auxiliary structure.

  * Receving an IPV4 packet
    Check if the packet is for the router and it is an ICMP ECHO Request,
    meaning that the router should send an ICMP ECHO REPLY MESSAGE.
    If it is not for the router, then there is a series of checks that have
    to be done in order to send the packet forward.
    ->Check the checksum and if it is wrong, drop the packet.
    ->Check the ttl and if it is wrong, send ICMP error message + 
    drop the packet.
    ->Check if the next hop is an existing one and if not, send ICMP
    destionation unreachable error message + drop the packet.

    If all the tests have been passed, than we should check if the router
    knows the mac of the next hop. 
    If the next hop is not saved in cache, then send an ARP Request in order
    to obtain the mac asociated with the next-hop.
    (In order to build an ARP Request, all the headers have to be build again
    use the send_arp_request function)
    If it was in the cache, then send the entry normally forward.
     	 
## DIFFICULTIES
    I had some difficulties because I have not correctly allocated some fields
    and there were a lot of problems with how pointer arithmetics works. 

