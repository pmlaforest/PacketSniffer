/*
Simple Sniffer with winpcap , prints ethernet , ip , tcp , udp and icmp headers along with data dump in hex
Author : Silver Moon ( m00n.silv3r@gmail.com ).
*/

#include <stdio.h>
#include <ctype.h>
#include <winsock2.h>   //need winsock for inet_ntoa and ntohs methods

#define HAVE_REMOTE
#include "protocol_headers.h"
#include "pcap.h"  

#define MAX_FILTER_STR 1000
#define NB_OF_KEYWORDS 3
#define NB_OF_EXPRESSIONS 5

#pragma comment(lib , "ws2_32.lib") //For winsock
#pragma comment(lib , "wpcap.lib") //For winpcap

//filters.c
int activate_packet_filter(pcap_t *adhandle, bpf_u_int32 netmask, char *filter_mask);

//some packet processing functions
void ProcessPacket(u_char*, int); //This will decide how to digest

void print_ethernet_header(u_char*);
void print_ipv6_packet(unsigned char*, int);
void PrintIpHeader(unsigned char*, int);
void print_arp_packet(unsigned char*, int);
void PrintIcmpPacket(u_char*, int);
void print_udp_packet(u_char*, int);
void PrintTcpPacket(u_char*, int);
void PrintData(u_char*, int);

// Restore the byte boundary back to the previous value
//#include <poppack.h>

FILE *logfile;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, arp = 0, ipv6 = 0, total = 0, total_others = 0, i, j;
struct sockaddr_in source, dest;
char hex[2];

//Its free!
ETHER_HDR *ethhdr;
IPV4_HDR *iphdr;
IPV6_HDR *ipv6hdr;
TCP_HDR *tcpheader;
UDP_HDR *udpheader;
ICMP_HDR *icmpheader;
u_char *data;

pcap_if_t *alldevs;
static u_char errbuf[PCAP_ERRBUF_SIZE];
static pcap_if_t  *d;

int select_interface_to_sniff(void) 
{
	u_int i, inum;

	/* The user didn't provide a packet source: Retrieve the local device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		return -1;
	}

	i = 0;
	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s\n    ", ++i, d->name);

		if (d->description)
		{
			printf(" (%s)\n", d->description);
		}
		else
		{
			printf(" (No description available)\n");
		}
	}

	if (i == 0)
	{
		fprintf(stderr, "No interfaces found! Exiting.\n");
		return -1;
	}

	printf("\nEnter the interface number you would like to sniff : ");
	scanf_s("%d", &inum);

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);
}

// converts string to uppercase
void str_toupper(char *str)
{
	char *temp_ptr;
	int c, d;

	temp_ptr = str;
	while (*temp_ptr != '\0') {
		// Character is alphabetic
		c = *temp_ptr;
		if ((d = isalpha(*temp_ptr)) != 0) {
			c = toupper(*temp_ptr);
			*temp_ptr = c;
		}
		temp_ptr++;
	}
}

// converts string to lowercase
void str_tolower(char *str)
{
	char *temp_ptr;
	unsigned char c, d, e;

	temp_ptr = str;
	while (*temp_ptr != '\0') {
		// Character is alphabetic
		e = *temp_ptr;
		if ((d = isalpha(e)) != 0) {
			c = tolower(e);
			*temp_ptr = c;
		}
		temp_ptr++;
	}
}

// removing newline from string
void strip_newline(char *str)
{
	char *tmp_str = str;

	while (*tmp_str != '\0') {
		if (*tmp_str == '\n') {
			*tmp_str = '\0';
			break;
		}
		tmp_str++;
	}
}

// flushing input buffer
void flush_nl_inputbuffer(void)
{
	while (getchar() != '\n');
}

// compare the filter expression against an array passed as an argument.
int validate_filter_substr(char *filter_word, char *filter_exp_to_comp[], int nbr_str)
{
	int word_nbr = 0;

	while (word_nbr < nbr_str) {
		if ((strncmp(filter_word, filter_exp_to_comp[word_nbr], strlen(filter_exp_to_comp[word_nbr]))) == 0) 
		{ 
			return 0; 
		}
		word_nbr++;
	}
	return -1;
}

// function called to verify the user string.
int validate_filter_str(char *filter_str, int filter_str_len) 
{
	// What an expression can contain : meaninful expressions (ip, tcp, etc) 
	// whitespaces and words AND, OR, NOT. 
	// No two expressions can be side by side : they need to be separated by an AND, OR, NOT.
	// If we cannot validate the expression, an error is returned.

	char *token;
	const char s[3] = " ";
	int field_in_exp = 0;
	char *expression[NB_OF_EXPRESSIONS] = { "ip", "tcp", "icmp", "igmp", "udp" };
	char *keyword[NB_OF_KEYWORDS] = { "and", "or", "not" };

	//Put the string in lowercase
	str_tolower(filter_str);

	// Creating a copy of the string, strtok destroys the string.
	char *temp_filter_buf = (char*)malloc((filter_str_len + 1) * sizeof(char));
	if (temp_filter_buf == NULL) {
		fprintf(stderr, "\nError allocating memory for temporary buffer\n");
		return -1;
	}
	memset(temp_filter_buf, '\0', (filter_str_len + 1));
	memcpy(temp_filter_buf, filter_str, filter_str_len);

	if (strncmp(temp_filter_buf, "", 1) == 0) 
	{
		return 1;
	}

	// OK to parse the copy since strtok destroys it.
	// Divide the string into expressions and keywords.
	token = strtok(temp_filter_buf, s);
	while (token != NULL) {
		// even fields number are words like ip, tcp, etc.
		if ((field_in_exp % 2) == 0)
		{
			if (validate_filter_substr(token, expression, NB_OF_EXPRESSIONS) != 0) {
				return -1;
			}
		}
		// odd fields are separators (and, or, not).
		else {
			if (validate_filter_substr(token, keyword, NB_OF_KEYWORDS) != 0) {
				return -1;
			}
		}
		token = strtok(NULL, s);
		field_in_exp++;
	}

	// We cannot end on a odd field.
	if ((field_in_exp % 2) == 0) {
		return -1;
	}

	return 0;
}

void display_filter_menu(void) 
{
	printf("\n*** You can add a filter by entering the protocol name. \n");
	printf("*** Note that you can combine them with AND, OR, NOT to get a mixed filter.\n");
	printf("*** For example to get TCP and IP packets, enter \"ip and tcp\".\n");
	printf("*** More examples can be found at https://www.winpcap.org/docs/docs_41/html/group__language.html\n\n");
	
	printf("Add filters (ENTER to sniff all incoming packets):\n");
}

int main()
{
	u_int res;
	u_char buffer[100];
	u_char *pkt_data;
	time_t seconds;
	struct tm tbreak;
	
	pcap_t *fp;
	struct pcap_pkthdr *header;
	bpf_u_int32  netmask;
	char chosen_filters[MAX_FILTER_STR];
	int filter_flag;
	int ret_filter_val = 0;

	fopen_s(&logfile, "log.txt", "w");

	if (logfile == NULL)
	{
		printf("Unable to create file.");
	}

	// up to the user to choose between the interfaces !
	if (select_interface_to_sniff() == -1) {
		return -1;
	}

	// Getting rid of old stuff.
	flush_nl_inputbuffer();
	
	/* Are we using a filter during this session ? */

	display_filter_menu();
	do {
		memset(chosen_filters, '\0', sizeof(chosen_filters));
		if (fgets(chosen_filters, sizeof(chosen_filters), stdin) == NULL) {
			fprintf(stderr, "\nError reading input from user\n");
			return -1;
		}

		strip_newline(chosen_filters);
		ret_filter_val = validate_filter_str(chosen_filters, sizeof(chosen_filters));

		if (ret_filter_val < 0) {
			printf("Error: wrong syntax\n");
		}
	} while (ret_filter_val < 0);

	if (!ret_filter_val) {
		printf("Packets filtered by %s\n", chosen_filters);
	}
	
	/* Open the device */
	if ((fp = pcap_open(d->name,
		100 /*snaplen*/,
		PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
		20 /*read timeout*/,
		NULL /* remote authentication */,
		errbuf)
		) == NULL)
	{
		fprintf(stderr, "\nError opening adapter\n");
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;

	if (!ret_filter_val) {
		activate_packet_filter(fp, netmask, chosen_filters);
	}

	//read packets in a loop :)
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		if (res == 0)
		{
			// Timeout elapsed
			continue;
		}
		seconds = header->ts.tv_sec;
		localtime_s(&tbreak, &seconds);
		strftime(buffer, 80, "%d-%b-%Y %I:%M:%S %p", &tbreak);
		//print pkt timestamp and pkt len
		//fprintf(logfile , "\nNext Packet : %ld:%ld (Packet Length : %ld bytes) " , header->ts.tv_sec, header->ts.tv_usec, header->len);
		fprintf(logfile, "\nNext Packet : %s.%ld (Packet Length : %ld bytes) ", buffer, header->ts.tv_usec, header->len);
		ProcessPacket(pkt_data, header->caplen);
	}

	if (res == -1)
	{
		fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(fp));
		return -1;
	}

	return 0;
}

void ProcessPacket(u_char* Buffer, int Size)
{
	//Ethernet header
	ethhdr = (ETHER_HDR *)Buffer;
	++total;

	//Ip packets
	if (ntohs(ethhdr->type) == 0x0800)
	{
		//ip header
		iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));

		switch (iphdr->ip_protocol) //Check the Protocol and do accordingly...
		{
		printf("Normal packet of %hx\n", ntohs(ethhdr->type));
		case 1: //ICMP Protocol
			icmp++;
			PrintIcmpPacket(Buffer, Size);
			break;

		case 2: //IGMP Protocol
			igmp++;
			break;

		case 6: //TCP Protocol
			tcp++;
			PrintTcpPacket(Buffer, Size);
			break;

		case 17: //UDP Protocol
			udp++;
			print_udp_packet(Buffer, Size);
			break;

		default: //Some Other Protocol like ARP etc.
			others++;
			break;
		}
	}
	
	//ARP Packet
	else if (ntohs(ethhdr->type) == 0x0806) {
		arp++;
		print_arp_packet(Buffer, Size);
	}

	//Ipv6 Packet
	else if (ntohs(ethhdr->type) == 0x86dd) {
		ipv6++;
		print_ipv6_packet(Buffer, Size);
	}

	else {
		printf("Strange packet of %hx\n", ntohs(ethhdr->type));
		total_others++;
	}

	printf("TCP :  %d\nUDP :  %d\nICMP : %d\nIGMP : %d\nARP : %d\nIPv6 : %d\nOthers : %d\nTotal_Others : %d\nTotal : %d" , tcp, udp, icmp, igmp, arp, ipv6, others, total_others, total);
	set_cursor_to_previous_line(8);
}

/*
Print the Ethernet header
*/
void print_ethernet_header(u_char* buffer)
{
	ETHER_HDR *eth = (ETHER_HDR *)buffer;

	fprintf(logfile, "\n");
	fprintf(logfile, "Ethernet Header\n");
	fprintf(logfile, " |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->dest[0], eth->dest[1], eth->dest[2], eth->dest[3], eth->dest[4], eth->dest[5]);
	fprintf(logfile, " |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->source[0], eth->source[1], eth->source[2], eth->source[3], eth->source[4], eth->source[5]);
	fprintf(logfile, " |-Protocol            : 0x%.4x \n", ntohs(eth->type));
}

int find_digit_in_nb(int number_to_scan)
{
	int n;
	n = 1;
	if (number_to_scan >= 100000000) { n += 8; number_to_scan /= 100000000; }
	if (number_to_scan >= 10000) { n += 4; number_to_scan /= 10000; }
	if (number_to_scan >= 100) { n += 2; number_to_scan /= 100; }
	if (number_to_scan >= 10) { n += 1; }

	return n;
}

void print_ipv6_packet(unsigned char* Buffer, int Size)
{
	int iphdrlen = 0;
	IN6_ADDR ipv6_src_addr;
	IN6_ADDR ipv6_dest_addr;
	char src_addr[50];
	char dest_addr[50];
	
	ipv6hdr = (IPV6_HDR *)(Buffer + sizeof(ETHER_HDR));

	//The version comes in the first niblet of the version's byte.
	//See an ipv6 packet on Wireshark.
	ipv6hdr->ipv6_version = ipv6hdr->ipv6_version >> 4;

	for (int word_ip_v6 = 0; word_ip_v6 < 8; word_ip_v6++) {
		ipv6_src_addr.u.Word[word_ip_v6] = ipv6hdr->ipv6_source_addr[word_ip_v6];
		ipv6_dest_addr.u.Word[word_ip_v6] = ipv6hdr->ipv6_source_addr[word_ip_v6];
	}

	memset(src_addr, '\0', sizeof(src_addr));
	memset(dest_addr, '\0', sizeof(dest_addr));

	InetNtop(AF_INET6, (void*)&ipv6_src_addr, src_addr, sizeof(src_addr));
	InetNtop(AF_INET6, (void*)&ipv6_dest_addr, dest_addr, sizeof(dest_addr));

	print_ethernet_header(Buffer);

	fprintf(logfile, "\n");
	fprintf(logfile, "IPv6 Header\n");
	fprintf(logfile, " |-IP Version : %d\n", (unsigned int)ipv6hdr->ipv6_version);
	fprintf(logfile, " |-Type Of Service : %d\n", (unsigned int)ipv6hdr->ipv6_tos);
	fprintf(logfile, " |-Flow Label : %d\n", (unsigned int)ipv6hdr->ipv6_flow_label);
	fprintf(logfile, " |-Payload : %d\n", (unsigned int)ipv6hdr->ipv6_payload);
	fprintf(logfile, " |-Next header : %d\n", (unsigned int)ipv6hdr->ipv6_next_header);
	fprintf(logfile, " |-Hop limit : %d\n", (unsigned int)ipv6hdr->ipv6_hop_limit);
	fprintf(logfile, " |-Source address : %s\n", src_addr);
	fprintf(logfile, " |-Dest address   : %s\n", dest_addr);
}

/*
Print ARP packet
*/
void print_arp_packet(unsigned char* Buffer, int Size)
{
	int arphdrlen = 0;
	ARP_HDR* arphdr;
	char mac_addr_src[24];
	char mac_addr_target[24];
	short hard_type = 0;
	short op_code = 0;

	arphdr = (ARP_HDR *)(Buffer + sizeof(ETHER_HDR));
	arphdrlen = sizeof(ARP_HDR) * 4;

	memset(mac_addr_src, '\0', sizeof(mac_addr_src));
	memset(mac_addr_target, '\0', sizeof(mac_addr_target));

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = arphdr->arp_sender_proto_addr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = arphdr->arp_target_proto_addr;

	hard_type = (arphdr->arp_hardw_type[0] << 8) + arphdr->arp_hardw_type[1];
	op_code = (arphdr->arp_opcode[0] << 8) + arphdr->arp_opcode[1];

	fprintf(logfile, "\n\n***********************ARP Packet*************************\n");

	print_ethernet_header(Buffer);

	fprintf(logfile, "\n");
	fprintf(logfile, "ARP Header\n");
	fprintf(logfile, " |-Hardware Type : %d\n", (unsigned int)hard_type);
	fprintf(logfile, " |-Protocol Type : 0x%.4x\n", (unsigned short)arphdr->arp_proto_type);
	fprintf(logfile, " |-Hardware Address Length : %d\n", (unsigned int)arphdr->arp_hardw_addr_length);
	fprintf(logfile, " |-Protocol Address Length : %d\n", (unsigned int)arphdr->arp_proto_addr_length);
	fprintf(logfile, " |-Opcode : %d\n", (unsigned int)op_code);
	fprintf(logfile, " |-Sender hardware address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", arphdr->arp_sender_hardw_addr[0], arphdr->arp_sender_hardw_addr[1], arphdr->arp_sender_hardw_addr[2],
	 arphdr->arp_sender_hardw_addr[3], arphdr->arp_sender_hardw_addr[4], arphdr->arp_sender_hardw_addr[5]);
	fprintf(logfile, " |-Sender protocol address : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logfile, " |-target hardware address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n\n", arphdr->arp_target_hardw_addr[0], arphdr->arp_target_hardw_addr[1], arphdr->arp_target_hardw_addr[2],
	  arphdr->arp_target_hardw_addr[3], arphdr->arp_target_hardw_addr[4], arphdr->arp_target_hardw_addr[5]);
	fprintf(logfile, " |-target protocol address : %s\n", inet_ntoa(dest.sin_addr));
}

/*
Print the IP header for IP packets
*/
void PrintIpHeader(unsigned char* Buffer, int Size)
{
	int iphdrlen = 0;

	iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
	iphdrlen = iphdr->ip_header_len * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;


	print_ethernet_header(Buffer);

	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	fprintf(logfile, " |-IP Version : %d\n", (unsigned int)iphdr->ip_version);
	fprintf(logfile, " |-IP Header Length : %d DWORDS or %d Bytes\n", (unsigned int)iphdr->ip_header_len, ((unsigned int)(iphdr->ip_header_len)) * 4);
	fprintf(logfile, " |-Type Of Service : %d\n", (unsigned int)iphdr->ip_tos);
	fprintf(logfile, " |-IP Total Length : %d Bytes(Size of Packet)\n", ntohs(iphdr->ip_total_length));
	fprintf(logfile, " |-Identification : %d\n", ntohs(iphdr->ip_id));
	fprintf(logfile, " |-Reserved ZERO Field : %d\n", (unsigned int)iphdr->ip_reserved_zero);
	fprintf(logfile, " |-Dont Fragment Field : %d\n", (unsigned int)iphdr->ip_dont_fragment);
	fprintf(logfile, " |-More Fragment Field : %d\n", (unsigned int)iphdr->ip_more_fragment);
	fprintf(logfile, " |-TTL : %d\n", (unsigned int)iphdr->ip_ttl);
	fprintf(logfile, " |-Protocol : %d\n", (unsigned int)iphdr->ip_protocol);
	fprintf(logfile, " |-Checksum : %d\n", ntohs(iphdr->ip_checksum));
	fprintf(logfile, " |-Source IP : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logfile, " |-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
}

/*
Print the TCP header for TCP packets
*/
void PrintTcpPacket(u_char* Buffer, int Size)
{
	unsigned short iphdrlen;
	int header_size = 0, tcphdrlen, data_size;

	iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
	iphdrlen = iphdr->ip_header_len * 4;

	tcpheader = (TCP_HDR*)(Buffer + iphdrlen + sizeof(ETHER_HDR));
	tcphdrlen = tcpheader->data_offset * 4;

	data = (Buffer + sizeof(ETHER_HDR) + iphdrlen + tcphdrlen);
	data_size = (Size - sizeof(ETHER_HDR) - iphdrlen - tcphdrlen);

	fprintf(logfile, "\n\n***********************TCP Packet*************************\n");

	PrintIpHeader(Buffer, Size);

	fprintf(logfile, "\n");
	fprintf(logfile, "TCP Header\n");
	fprintf(logfile, " |-Source Port : %u\n", ntohs(tcpheader->source_port));
	fprintf(logfile, " |-Destination Port : %u\n", ntohs(tcpheader->dest_port));
	fprintf(logfile, " |-Sequence Number : %u\n", ntohl(tcpheader->sequence));
	fprintf(logfile, " |-Acknowledge Number : %u\n", ntohl(tcpheader->acknowledge));
	fprintf(logfile, " |-Header Length : %d DWORDS or %d BYTES\n", (unsigned int)tcpheader->data_offset, (unsigned int)tcpheader->data_offset * 4);
	fprintf(logfile, " |-CWR Flag : %d\n", (unsigned int)tcpheader->cwr);
	fprintf(logfile, " |-ECN Flag : %d\n", (unsigned int)tcpheader->ecn);
	fprintf(logfile, " |-Urgent Flag : %d\n", (unsigned int)tcpheader->urg);
	fprintf(logfile, " |-Acknowledgement Flag : %d\n", (unsigned int)tcpheader->ack);
	fprintf(logfile, " |-Push Flag : %d\n", (unsigned int)tcpheader->psh);
	fprintf(logfile, " |-Reset Flag : %d\n", (unsigned int)tcpheader->rst);
	fprintf(logfile, " |-Synchronise Flag : %d\n", (unsigned int)tcpheader->syn);
	fprintf(logfile, " |-Finish Flag : %d\n", (unsigned int)tcpheader->fin);
	fprintf(logfile, " |-Window : %d\n", ntohs(tcpheader->window));
	fprintf(logfile, " |-Checksum : %d\n", ntohs(tcpheader->checksum));
	fprintf(logfile, " |-Urgent Pointer : %d\n", tcpheader->urgent_pointer);
	fprintf(logfile, "\n");
	fprintf(logfile, " DATA Dump ");
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData((u_char*)iphdr, iphdrlen);

	fprintf(logfile, "TCP Header\n");
	PrintData((u_char*)tcpheader, tcphdrlen);

	fprintf(logfile, "Data Payload\n");
	PrintData(data, data_size);

	fprintf(logfile, "\n###########################################################\n");
}

/*
Print the UDP header for UDP packets
*/
void print_udp_packet(u_char *Buffer, int Size)
{
	int iphdrlen = 0, data_size = 0;

	iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
	iphdrlen = iphdr->ip_header_len * 4;

	udpheader = (UDP_HDR*)(Buffer + iphdrlen + sizeof(ETHER_HDR));

	data = (Buffer + sizeof(ETHER_HDR) + iphdrlen + sizeof(UDP_HDR));
	data_size = (Size - sizeof(ETHER_HDR) - iphdrlen - sizeof(UDP_HDR));

	fprintf(logfile, "\n\n***********************UDP Packet*************************\n");

	PrintIpHeader(Buffer, Size);

	fprintf(logfile, "\nUDP Header\n");
	fprintf(logfile, " |-Source Port : %d\n", ntohs(udpheader->source_port));
	fprintf(logfile, " |-Destination Port : %d\n", ntohs(udpheader->dest_port));
	fprintf(logfile, " |-UDP Length : %d\n", ntohs(udpheader->udp_length));
	fprintf(logfile, " |-UDP Checksum : %d\n", ntohs(udpheader->udp_checksum));

	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData((u_char*)iphdr, iphdrlen);

	fprintf(logfile, "UDP Header\n");
	PrintData((u_char*)udpheader, sizeof(UDP_HDR));

	fprintf(logfile, "Data Payload\n");
	PrintData(data, data_size);

	fprintf(logfile, "\n###########################################################\n");
}

void PrintIcmpPacket(u_char* Buffer, int Size)
{
	int iphdrlen = 0, icmphdrlen = 0, data_size = 0;

	iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
	iphdrlen = iphdr->ip_header_len * 4;

	icmpheader = (ICMP_HDR*)(Buffer + iphdrlen + sizeof(ETHER_HDR));

	data = (Buffer + sizeof(ETHER_HDR) + iphdrlen + sizeof(ICMP_HDR));
	data_size = (Size - sizeof(ETHER_HDR) - iphdrlen - sizeof(ICMP_HDR));

	fprintf(logfile, "\n\n***********************ICMP Packet*************************\n");
	PrintIpHeader(Buffer, Size);

	fprintf(logfile, "\n");

	fprintf(logfile, "ICMP Header\n");
	fprintf(logfile, " |-Type : %d", (unsigned int)(icmpheader->type));

	if ((unsigned int)(icmpheader->type) == 11)
	{
		fprintf(logfile, " (TTL Expired)\n");
	}
	else if ((unsigned int)(icmpheader->type) == 0)
	{
		fprintf(logfile, " (ICMP Echo Reply)\n");
	}

	fprintf(logfile, " |-Code : %d\n", (unsigned int)(icmpheader->code));
	fprintf(logfile, " |-Checksum : %d\n", ntohs(icmpheader->checksum));
	fprintf(logfile, " |-ID : %d\n", ntohs(icmpheader->id));
	fprintf(logfile, " |-Sequence : %d\n", ntohs(icmpheader->seq));
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData((u_char*)iphdr, iphdrlen);

	fprintf(logfile, "ICMP Header\n");
	PrintData((u_char*)icmpheader, sizeof(ICMP_HDR));

	fprintf(logfile, "Data Payload\n");
	PrintData(data, data_size);

	fprintf(logfile, "\n###########################################################\n");
}

/*
Print the hex values of the data
*/
void PrintData(u_char* data, int Size)
{
	unsigned char a, line[17], c;
	int j;

	//loop over each character and print
	for (i = 0; i < Size; i++)
	{
		c = data[i];

		//Print the hex value for every character , with a space
		fprintf(logfile, " %.2x", (unsigned int)c);

		//Add the character to data line
		a = (c >= 32 && c <= 128) ? (unsigned char)c : '.';

		line[i % 16] = a;

		//if last character of a line , then print the line - 16 characters in 1 line
		if ((i != 0 && (i + 1) % 16 == 0) || i == Size - 1)
		{
			line[i % 16 + 1] = '\0';

			//print a big gap of 10 characters between hex and characters
			fprintf(logfile, "          ");

			//Print additional spaces for last lines which might be less than 16 characters in length
			for (j = strlen(line); j < 16; j++)
			{
				fprintf(logfile, "   ");
			}

			fprintf(logfile, "%s \n", line);
		}
	}
	fprintf(logfile, "\n");
}