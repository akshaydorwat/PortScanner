#include "Scan.hpp"

void Scan::toString(){
		LOG(DEBUG, \
			"\n\t\t\tSource IP and Port      : " + string(inet_ntoa(src.sin_addr)) + " : " + to_string((int)src.sin_port) + "\n" \
			"\t\t\tDestination IP and Port : " + string(inet_ntoa(dst.sin_addr)) + " : " +  to_string((int)dst.sin_port) + "\n" \
			"\t\t\tScan Type               : " + scanType);
}

const u_char* Scan::basicFilter(const u_char *packet, uint8_t &protocol){
	int runner = 0;
	u_int16_t ether_type;
	uint32_t source;
	uint32_t dest;
	struct ip *header;
	
	// get the network layer protocol
	const struct ether_header *ether = (struct ether_header *) packet;
	ether_type = ntohs(ether->ether_type);
	runner = runner + ETHER_HDR_LEN;
	
	switch(ether_type){
	case ETHERTYPE_IP:
		// IP protocol
		header = (struct ip *) (packet + runner);
		//verify IP v4 
		if(header->ip_v != IPVERSION) 
			return NULL;
		// compare the source and destination ip
		source = (header->ip_dst.s_addr);
		dest = (header->ip_src.s_addr);
		if((memcmp(&source, &src.sin_addr.s_addr, sizeof(uint32_t)) != 0 ) || 
		   (memcmp(&dest, &dst.sin_addr.s_addr, sizeof(uint32_t)) != 0)){
			return NULL;
		}
		// get transport level protocol
		protocol = header->ip_p;
		runner = runner + (int)((header->ip_hl*32)/8);
		return (u_char*)(packet + runner);
		break;

	default:
		return NULL;
	}

}
 
