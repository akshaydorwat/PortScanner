/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/


#include "UDPscan.hpp"

void UDPscan::createPacket(){

	int qLen;
	uint16_t pLen;
	struct UDP_pseudo_t temp;
	
	// set source port
	factory->setOption("src_port", (void *)&src.sin_port);
	
	// set destination port
	factory->setOption("dst_port", (void *)&dst.sin_port);
	
	// set dns request id
	uint16_t id = getpid();
	factory->setOption("id", (void *)&id );
	
	// set recursion desired
	factory->setOption("rd", NULL);
	
	// set OPCODE
	uint16_t opcode = OPCODE_QUERY;
	factory->setOption("opcode", &opcode);
	
	// set qcount 1
	uint16_t qcount = 1;
	factory->setOption("q_count", &qcount);
	
	//set quection section
	char searchStr[] = "www.iu.edu";
	qLen = factory->setQuestion(searchStr, TYPE_A, CLASS_INTERNET);

	
	//set len 
	packetLen = sizeof(udphdr) + sizeof(dnshdr) + qLen;
	pLen = sizeof(udphdr) + sizeof(dnshdr) + qLen;
	factory->setOption("len", &packetLen);
	
	// set checksum
	temp.saddr = src.sin_addr.s_addr;
	temp.daddr = dst.sin_addr.s_addr;
	temp.reserve = 0;
	temp.protocol = IPPROTO_UDP;
	temp.len = htons(packetLen);
	factory->setOption("check", &temp);
}

void UDPscan::init(){
	int zero = 0;
	const int *val = &zero;

	// create packet 
	createPacket();

	// create raw socket
	sfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
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

void UDPscan::send(){
	if(sendto(sfd, buff, packetLen, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0){
		LOG(ERROR, "Sending failed");
	}else{
		LOG(DEBUG, debugInfo + " packet sent successfully");
		numOfPacketSent++;
	}
}

void UDPscan::handle(){
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

	// update status if no packet recieved
	if(numOfPacketReceived == 0){
		status = FILTERED;
	}

	// report states
	reportStats();

}

void UDPscan::filterCallback(const u_char *packet){
	uint8_t protocol;
	uint8_t type;
	uint8_t code;
	/*uint16_t s_port;
	uint16_t d_port;
	uint32_t source;
	uint32_t dest;
	int runner = 0;*/
	const u_char *retPtr;
	/*	const struct tcphdr *tcp_hdr;
	const struct icmp *icmp_hdr;
	const struct ip *icmp_ip_hdr;*/

	
	retPtr = basicFilter(packet, protocol);
	if(retPtr == NULL){
		return;
	}
	
	switch(protocol){
	//TCP protocol
    case IPPROTO_UDP: 
		LOG(DEBUG, debugInfo + " GOT UDP packet");
	}
}


