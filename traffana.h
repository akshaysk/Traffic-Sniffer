#ifndef _TRAFFANA_H_
#define _TRAFFANA_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#define MAXLOGSIZE	256
#define SIZE_ETHERNET 14
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
struct command_line_args
{
 	int verbose,tuple;
	float timeEpoch;
	char *interface, *readFileName, *writeFileName; 
};

struct flowLinkList
{
	char *address_string;
	struct flowLinkList *next;
};

static const struct option longOpts[] = {
	{"verbose", no_argument, NULL, 'v'},
	{"read", required_argument, NULL, 'r'},
	{"int", required_argument, NULL, 'i'},
	{"time", required_argument, NULL, 'T'},
	{"write", required_argument, NULL, 'w'},
	{"track", required_argument, NULL, 'z'},
	{0,0,0,0}
};

struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	u_int th_seq;		/* sequence number */
	u_int th_ack;		/* acknowledgement number */

	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

struct sniff_udp {
	u_short th_sport;
	u_short th_dport;
	u_short udp_len;
	u_short th_sum;
};


FILE *fp;
int total_count = 0, tcp_count = 0, udp_count = 0, icmp_count = 0, others_count = 0, total_bytes = 0;
int no_of_flows = 0, tcp_flows = 0, udp_flows = 0;
double ref_time = -1, time = 0;

struct flowLinkList *head = NULL;
#endif
