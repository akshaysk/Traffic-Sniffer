#include "traffana.h"

void LOG(FILE *fp,char *format,...)
{
	va_list arguments;
	char message[MAXLOGSIZE];
	int msgsize;
	va_start(arguments,format);
	msgsize = vsnprintf(message,sizeof(message),format,arguments);
	va_end(arguments);
	if(msgsize < 0)
		return;
	fprintf(fp,"%s",message);
	fflush(fp);
	exit(0);

}


void parse_command_line(int argc, char **argv, struct command_line_args *ob)
{
	int opt = 0, longIndex = 0;
	memset(ob,'\0',sizeof(struct command_line_args));
	opt = getopt_long_only(argc, argv, ":vi:r:T:w:z:", longOpts, &longIndex);
	if(opt == -1)
		LOG(stdout,"usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}] \n");
	while (opt != -1)
	{
		switch(opt) 
		{
			case 'r':
				if(*optarg == '-')
					LOG(stdout,"usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]n");
				ob->readFileName = optarg;
				break;		
			case 'w':
				if(*optarg == '-')
					LOG(stdout,"usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]n");
				ob->writeFileName = optarg;
				break;		
			case 'i':
				if(*optarg == '-')
					LOG(stdout,"usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]n");
				ob->interface = optarg;
				break;	
			case 'v':
				ob->verbose = 1;
				break;

			case 'T':
				if(*optarg == '-')
					LOG(stdout,"usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]n");
				ob->timeEpoch = atof(optarg);
				break;				

			case 'z':
				if(*optarg == '-')
					LOG(stdout,"usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]n");
				ob->tuple = atoi(optarg);
				if(!((ob->tuple == 2) || (ob->tuple == 5)))
					LOG(stdout, "Invalid argument value for option -z");	
				break;
			case '?':
			case ':':
			default :
				LOG(stdout,"usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]n");

		}

	opt = getopt_long_only(argc, argv, "vi:r:T:w:z:", longOpts, &longIndex);
	}
	
	if(ob->timeEpoch == 0)
		ob->timeEpoch = 1;
	
	if(ob->tuple == 0)
		ob->tuple = 2;
	if(ob->writeFileName)
	{
		fp = fopen(ob->writeFileName,"w");
		if(!fp)
		{
			LOG(stdout,"usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [ -z {2|5}]n");
		}
	}	
	else 
		fp = stdout;	
}

void print_op(struct command_line_args *object)
{
	if(object->verbose)
			fprintf(fp,"\n%lf %d %d %d %d %d %d %d %d %d", ref_time, total_count, total_bytes, no_of_flows, tcp_count, udp_count, icmp_count, others_count, tcp_flows, udp_flows);
	else
		fprintf(fp,"\n%lf %d %d %d", ref_time, total_count, total_bytes, no_of_flows); 
	struct flowLinkList *p = head;
	while(p!=NULL)
	{
		fprintf(fp,"\n%s->",p->address_string);
		p = p->next;
	}
	fprintf(fp,"\n");

	fflush(fp);
}

struct flowLinkList * create_node(char *mystring)
{
	struct flowLinkList * newNode = (struct flowLinkList *)malloc(sizeof(struct flowLinkList));
	if(!newNode)
	{
		LOG(stdout, "Error in allocating new node");
	}
	newNode->address_string = (char *)malloc(strlen(mystring)+1);
	memset(newNode->address_string, '\0', strlen(mystring));
	strncpy(newNode->address_string, mystring, strlen(mystring));
	newNode->next = NULL;
	no_of_flows++;
	int len = strlen(mystring);
	if(mystring[len - 1] == 'g')
		tcp_flows++;
	else if(mystring[len - 1] == 'r')
		udp_flows++;
	return newNode;
	
}

void delete_list()
{
	struct flowLinkList *p = head;
	while(p!=NULL)
	{
		head = head->next;
		p->next = NULL;
		free(p);
		p = head;
	}
}

void append_to_flow_list(char *string, int tuple)
{
	int flag = 0;
	struct flowLinkList *p;	
	if(head == NULL)
	{
		head = create_node(string);
		return;
	}

	p = head;

	if(tuple == 2)
	{
		while(p!=NULL)
		{
			if(strncmp(p->address_string, string, strlen(string)-1) == 0)
			{
				flag = 1;	
				break;
			}
			p = p->next;
		}
	}

	else if(tuple == 5)
	{
		while(p!=NULL)
		{
			if(strncmp(p->address_string, string, strlen(string)) == 0)
			{
				flag = 1;	
				break;
			}
			p = p->next;
		}				
	}

	if(flag == 0)
	{
		p = create_node(string);
		p->next = head;
		head = p;
	}

}

void count_flow(u_char *object, const struct sniff_ip *ip, const u_char *packet)
{
	const struct sniff_tcp *tcp;
	const struct sniff_udp *udp;
	u_short src_port_no = 0, dst_port_no = 0;
	struct in_addr src_addr, dst_addr;
	char *ip_string;
	int src_ip_len = 0, dst_ip_len = 0;
	int size_ip = 0;

	size_ip = IP_HL(ip)*4;	
	if(ip->ip_p == 0x06 || ip->ip_p == 0x11)
	{
		ip_string = (char *)malloc(MAXLOGSIZE);
		memset(ip_string,'\0',MAXLOGSIZE);

		memcpy(&src_addr,&(ip->ip_src),sizeof(struct in_addr));
		memcpy(&dst_addr,&(ip->ip_dst),sizeof(struct in_addr));
		src_ip_len = strlen(inet_ntoa(src_addr));
		dst_ip_len = strlen(inet_ntoa(dst_addr));
		strncpy(ip_string,inet_ntoa(src_addr),src_ip_len);
		ip_string[src_ip_len] = ',';
		strncpy(ip_string+src_ip_len+1,inet_ntoa(dst_addr),dst_ip_len);
		ip_string[src_ip_len + dst_ip_len + 1] = ',';	
			
		if(((struct command_line_args *)object)->tuple == 2)
			sprintf(ip_string + src_ip_len + dst_ip_len + 2, "%c",'a'+ip->ip_p);

		else if(((struct command_line_args *)object)->tuple == 5)
		{
			if(ip->ip_p == 0x06)
			{
				tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
				src_port_no = ntohs(tcp->th_sport);
				dst_port_no = ntohs(tcp->th_dport);
				sprintf(ip_string + src_ip_len + dst_ip_len + 2, "%d,%d,%c", src_port_no, dst_port_no,'a'+ip->ip_p);
			}
			else if(ip->ip_p == 0x11)
			{
				udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
				src_port_no = ntohs(udp->th_sport);
				dst_port_no = ntohs(udp->th_dport);
				sprintf(ip_string + src_ip_len + dst_ip_len + 2, "%d,%d,%c", src_port_no, dst_port_no,'a'+ip->ip_p);
			}

		}
			
		append_to_flow_list(ip_string,((struct command_line_args *)object)->tuple);
	}


}

void read_packets(u_char *object, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
{ 
	float delta = ((struct command_line_args *)object)->timeEpoch;
	const struct sniff_ip *ip;
	int version = 0;
	const struct sniff_tcp *tcp;
	int size_ip = 0, size_tcp = 0;

	time = (pkthdr->ts.tv_sec*1000000L + pkthdr->ts.tv_usec)/(double)1000000L;

	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	version = ip->ip_vhl >> 4;
	size_ip = IP_HL(ip)*4;	

	if(version != 4)
		return;
	if(size_ip < 20)
		return;

	if(ip->ip_p == 0x06)
	{
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20) {
			return;
		}

	}

	if(ref_time == -1)
		ref_time = time;

	if(time - ref_time < delta)
	{
			total_bytes += pkthdr->len; 
			total_count++; 
			count_flow(object, ip, packet);
	}

	else if((time - ref_time) >= delta)
	{

		print_op((struct command_line_args *)object);
		no_of_flows = 0;
		tcp_flows = 0; udp_flows = 0;		
		total_count = 0;
		total_bytes = 0;
		tcp_count = 0;
		udp_count = 0;
		icmp_count = 0;
		others_count = 0;
		delete_list();
		ref_time = ref_time + delta;
		if(time - ref_time > delta)
		{
			while(time - ref_time > delta)
			{
				print_op((struct command_line_args *)object);
				ref_time = ref_time + delta;
			}

		}
		total_bytes = pkthdr->len;
		total_count = 1;
		count_flow(object, ip, packet);
	}

	if(ip->ip_p == 0x01)
		icmp_count++;
	else if(ip->ip_p == 0x06)
		tcp_count++;
	else if(ip->ip_p == 0x11)
		udp_count++;
	else
		others_count++;

}

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct command_line_args object;
	parse_command_line(argc,argv,&object);	
	
	if(object.readFileName && object.interface)
	{
		LOG(stderr, "Either interface or input should be specified");
		exit(0);
	}
	
	if(object.readFileName)
	{
		if( (handle = pcap_open_offline(object.readFileName, errbuf)) == NULL)
		{
			LOG(stderr, "Error opening dump file");
			exit(0);
		}

	}

	else if(object.interface)
	{
		dev = object.interface;
		
		handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
		if (handle == NULL) {
			LOG(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(0);
		}

	}
	else
	{
		LOG(stderr, "No interface or input file is specified\n");
		exit(0);
	}
	pcap_loop(handle, -1, read_packets, (u_char *)&object);

	print_op(&object);
	fclose(fp);
	return(0);
}
