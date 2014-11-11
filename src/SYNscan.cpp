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
		LOG(DEBUG,"Socket Initialized");
    }
    // set IPHDRINCL fasle                                                                                        
    if(setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(zero)) < 0){
        LOG(ERROR, "Unable to set socket option IPHDEINCL to Flase");
        exit(-1);
    }else{
		LOG(DEBUG, "IPHDRINCL set to False");
    }
}

void SYNscan::send(){
	if(sendto(sfd, buff, sizeof(struct tcphdr), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0){
		LOG(ERROR, "Sending failed");
	}else{
		
		LOG(DEBUG, "PACKET sent successfully");
		numOfPacketSent++;
	}
}

void SYNscan::handle(){

	// Initialise the packet and socket
	init();
	
	// register callback with filter
	PacketScanner *scanner =  PacketScanner::getPacketScanner();	
	scanner->registerCallback(sfd, bind(&Scan::filterCallback, this, std::placeholders::_1));
	
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
	scanner->unregisterCallback(sfd);

	// report states
	reportStats();
}

void SYNscan::filterCallback(const u_char *packet){
	int runner = 0;
	u_int16_t ether_type;
	
	{
		// get the network layer protocol
		const struct ether_header *header = (struct ether_header *) packet;
		ether_type = ntohs(header->ether_type);
		runner = runner + ETHER_HDR_LEN;
	}
		
	switch(ether_type){

	case ETHERTYPE_IP:
		// IP protocol
		/*{
			const struct ip *header = (struct ip *) (packet + runner);
			//verify IP v4 
			if(header->version != IPVERSION) {return;}
			// compare the source and destination ip
			if((memcmp(&ntohl(header->ip_src), &src.sin_addr.s_addr, sizeof(header->ip_src)) != 0 ) || 
			   (memcmp(&ntohl(header->ip_dst), &dst.sin_addr.s_addr, sizeof(header->ip_dst)) != 0)){
				return;
			}
			}*/
		break;

	default:
		return;
	}
}

void SYNscan::reportStats(){

}

