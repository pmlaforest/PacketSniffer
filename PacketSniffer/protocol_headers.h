#pragma once

#include <stdio.h>
#include <sys/types.h>

// Set the packing to a 1 byte boundary
//#include "pshpack1.h"
//Ethernet Header
typedef struct ethernet_header
{
	UCHAR dest[6];
	UCHAR source[6];
	USHORT type;
}   ETHER_HDR, *PETHER_HDR, FAR * LPETHER_HDR, ETHERHeader;

/*Ip header (v4)
 There is no ECN field in the IPv4 header and no flags field. No padding neither.
 (see william stalling data and computer communication (8th edition) p578 )
*/
typedef struct ip_hdr
{
	unsigned char ip_header_len : 4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version : 4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier

	unsigned char ip_frag_offset : 5; // Fragment offset field

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1; //fragment offset

	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR;

//UDP header
typedef struct udp_hdr
{
	unsigned short source_port; // Source port no.
	unsigned short dest_port; // Dest. port no.
	unsigned short udp_length; // Udp packet length
	unsigned short udp_checksum; // Udp checksum (optional)
} UDP_HDR;

// TCP header
typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns : 1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1 : 3; //according to rfc
	unsigned char data_offset : 4; /*The number of 32-bit words in the TCP header.
								   This indicates where the data begins.
								   The length of the TCP header is always a multiple
								   of 32 bits.*/

	unsigned char fin : 1; //Finish Flag
	unsigned char syn : 1; //Synchronise Flag
	unsigned char rst : 1; //Reset Flag
	unsigned char psh : 1; //Push Flag
	unsigned char ack : 1; //Acknowledgement Flag
	unsigned char urg : 1; //Urgent Flag

	unsigned char ecn : 1; //ECN-Echo Flag
	unsigned char cwr : 1; //Congestion Window Reduced Flag

						   ////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;

typedef struct icmp_hdr
{
	BYTE type; // ICMP Error type
	BYTE code; // Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
} ICMP_HDR;

#pragma pack(2)

typedef struct ipv6_hdr
{
	unsigned char ipv6_version;
	unsigned char ipv6_tos;
	unsigned int ipv6_flow_label : 20;
	unsigned short ipv6_payload;
	unsigned char ipv6_next_header;
	unsigned char ipv6_hop_limit;
	unsigned short ipv6_source_addr[8];
	unsigned short ipv6_dest_addr[8];
} IPV6_HDR;

typedef struct  arp_hdr
{
	unsigned char arp_hardw_type[2];				// Hardware Type
	unsigned short arp_proto_type;					// Protocol Type
	unsigned char arp_hardw_addr_length;			// Hardware Address Length
	unsigned char arp_proto_addr_length;			// Protocol Address Length
	unsigned char arp_opcode[2];					// ARP opcode

	unsigned char arp_sender_hardw_addr[6];			// ARP sender hardware address (first two bytes)

	unsigned int arp_sender_proto_addr;				// ARP sender protocol address

	unsigned char arp_target_hardw_addr[6];			// ARP target hardware address (first two bytes)

	unsigned int arp_target_proto_addr;				// ARP target protocol address
} ARP_HDR;

/*Ip header (v6)
*/



