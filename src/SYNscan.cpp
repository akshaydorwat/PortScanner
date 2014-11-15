/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#include "SYNscan.hpp"

void SYNscan::createPacket(){

	struct TCP_pseudo_t temp;
	
	// set source port
	factory->setOption("src_port", (void *)&src.sin_port);

	// set destination port
	factory->setOption("dst_port", (void *)&dst.sin_port);

	// set seq num
	uint32_t seq = DEFAULT_SEQ_NO;
	factory->setOption("seq_no", (void *)&seq);

	// set ack seq num
	uint16_t ack_seq = DEFAULT_ACK_SEQ;
	factory->setOption("ack_seq", (void *)&ack_seq);

	// set data offset 
	uint16_t doff = DEFAULT_DATA_OFFSET;
	factory->setOption("doff", (void *)&doff);

	// set SYN flag
	factory->setOption("syn",NULL);

	// set window size
	uint16_t window = DEFAULT_WINDOW;
	factory->setOption("window", (void *)&window);

	// set checksum
	temp.saddr = src.sin_addr.s_addr;
	temp.daddr = dst.sin_addr.s_addr;
	temp.reserve = 0;
	temp.protocol = IPPROTO_TCP;
	temp.len = htons(sizeof(struct tcphdr));
	factory->setOption("check", &temp);
}

void SYNscan::init(){
	
	int zero = 0;
	const int *val = &zero;

	// create packet 
	createPacket();

	// create raw socket
	sfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(sfd < 0 ){
		LOG(ERROR,"Failed to create RAW socket");
		exit(0);
	}else{
		//LOG(DEBUG,"Socket Initialized");
	}
	// set IPHDRINCL fasle                                                                                       
	if(setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(zero)) < 0){
		LOG(ERROR, "Unable to set socket option IPHDEINCL to Flase");
		exit(-1);
	}else{
		//LOG(DEBUG, "IPHDRINCL set to False");
	}
}

void SYNscan::send(){
	if(sendto(sfd, buff, sizeof(struct tcphdr), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0){
		LOG(ERROR, "Sending failed");
	}else{
		
		LOG(DEBUG, debugInfo + " packet sent successfully");
		numOfPacketSent++;
	}
}

void SYNscan::handle(){

	// Initialise the packet and socket
	init();
	
	// register callback with filter
	PacketScanner &scanner =  PacketScanner::getPacketScanner();	
	scanner.registerCallback(sfd, bind(&Scan::filterCallback, this, std::placeholders::_1));
	
	// send packet
	send();
	
	// Poll on the recieved packet, if failed try resending it
	for(int i=0 ; i < MAX_TRY; i++){
	 
		sleep(1);
		if(numOfPacketReceived){
			break;
		}
		send();
	}

	// unregister callback wih filter
	scanner.unregisterCallback(sfd);

	// update status if no packet recieved
	if(numOfPacketReceived == 0){
		status = FILTERED;
	}

	// report states
	reportStats();
}

void SYNscan::filterCallback(const u_char *packet){
	
	uint8_t protocol;
	uint8_t type;
	uint8_t code;
	uint16_t s_port;
	uint16_t d_port;
	uint32_t source;
	uint32_t dest;
	int runner = 0;
	const u_char *retPtr;
	const struct tcphdr *tcp_hdr;
	const struct icmp *icmp_hdr;
	const struct ip *icmp_ip_hdr;

	
	retPtr = basicFilter(packet, protocol);
	if(retPtr == NULL){
		return;
	}
	
	switch(protocol){
	//TCP protocol
    case IPPROTO_TCP:
		tcp_hdr = (struct tcphdr *)retPtr;
		s_port = ntohs(tcp_hdr->source);
		d_port = ntohs(tcp_hdr->dest);
		
		// compare the ports
		if((memcmp(&s_port, &dst.sin_port, sizeof(uint16_t)) != 0) || 
		   (memcmp(&d_port, &src.sin_port, sizeof(uint16_t)) != 0)){
			//LOG(DEBUG, "Ports didnt match");
			return;
		}

		// recieved the response
		numOfPacketReceived++;
		
		// check flags in tcp packet
		if((tcp_hdr->syn) && (tcp_hdr->ack)){
			status = OPEN;
 			LOG(DEBUG, debugInfo + " SYN & ACK flag set, Port is OPEN");
		}
		else if((tcp_hdr->syn)){
			status = OPEN;
			LOG(DEBUG, debugInfo + " SYN flag set, Port is OPEN");
		}
		else if((tcp_hdr->rst)){
			status = CLOSED;
			LOG(DEBUG, debugInfo + " RST flag set, Port is closed");
		}
		break;
		
	// ICMP protocol
    case IPPROTO_ICMP:
		icmp_hdr = (struct icmp *)retPtr;
		type = icmp_hdr->icmp_type;
		code = icmp_hdr->icmp_code;
		
		switch(type){
			// Host unreachable
		case ICMP_UNREACH:
			switch(code){
			case ICMP_UNREACH_HOST:
			case ICMP_UNREACH_PROTOCOL:
			case ICMP_UNREACH_PORT:
			case ICMP_UNREACH_NET_PROHIB:
			case ICMP_UNREACH_HOST_PROHIB:
			case ICMP_UNREACH_FILTER_PROHIB:
				// verify ip packet
				icmp_ip_hdr = &icmp_hdr->icmp_ip;
				source = icmp_ip_hdr->ip_src.s_addr;
				dest =   icmp_ip_hdr->ip_dst.s_addr;
				//LOG(DEBUG, "Source :" + string(inet_ntoa(icmp_ip_hdr->ip_src)));
				//LOG(DEBUG,"Destination : " + string(inet_ntoa(icmp_ip_hdr->ip_dst)));
				if((memcmp(&source, &src.sin_addr.s_addr, sizeof(uint32_t)) != 0 ) || 
				   (memcmp(&dest, &dst.sin_addr.s_addr, sizeof(uint32_t)) != 0)){
					return;
				}

				// get transport level protocol
				protocol = icmp_ip_hdr->ip_p;
				if(protocol != IPPROTO_TCP) return;
				// check source and desination port
				runner = runner + (int)((icmp_ip_hdr->ip_hl*32)/8);
				tcp_hdr = (struct tcphdr *)((u_char*)icmp_ip_hdr+runner);
				s_port = ntohs(tcp_hdr->source);
				d_port = ntohs(tcp_hdr->dest);
				//LOG(DEBUG, "Source port :" + to_string((int)s_port));
				//LOG(DEBUG, "dest port :" + to_string((int)d_port));
				if((memcmp(&d_port, &dst.sin_port, sizeof(uint16_t)) != 0) || 
				   (memcmp(&s_port, &src.sin_port, sizeof(uint16_t)) != 0)){
					return;
				}
				// set status 
				numOfPacketReceived++;
				status = FILTERED;
				LOG(DEBUG, debugInfo + " UNREACHABLE HOST, Port is FILTERED");
				break;

			default:
				return;
			}// code
			break;
			
		default:
			return;
		}//type
		break;

    default :
		return;
	}//protocol
}


