/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#include "PacketFactory.hpp"

// Global declaration of static variable
bitset<MAX_PORT> PacketFactory::portRange;
Mutex PacketFactory::mLock;

bool PacketFactory::setOption(string option, void *ptr){
  
	bool ret;

    switch(protocol){
		
    case TCP :
		ret =  setOptionTCP(option, ptr);
		break;

    case ICMP:
		break;

    case UDP:
		break;
		
    default:
		LOG(ERROR, "Invalid Protocol");
		ret = false;
    }
	return ret;
}

bool PacketFactory::setOptionTCP(string &option, void *val){

	struct tcphdr *tcp = (struct tcphdr*)packet;
	
	// source port
	if(option.compare("src_port") == 0){
		uint16_t *port = (uint16_t*)val;
		*port  = PacketFactory::getUnusedPort();
		LOG(DEBUG, "Source Port : " + to_string(*port));
		tcp->source = htons(*port);
	} else

	// destination port
	if(option.compare("src_port") == 0){
		uint16_t *port = (uint16_t*)val;
		tcp->dest = htons(*port);
	} else

	// sequence number
	if(option.compare("seq_no") == 0){				
		uint32_t *seq = (uint32_t*)val;
		tcp->seq = htonl(*seq);
	}else

	// acknowlegement  sequence number
	if(option.compare("ack_seq") == 0){
		uint16_t *ack_seq = (uint16_t*)val;
		tcp->ack_seq = htons(*ack_seq);
	}else
	
	// data offset
	if(option.compare("doff") == 0){
		uint16_t *doff = (uint16_t*)val;
		tcp->doff = htons(*doff);
	}else

	// finish flag
	if(option.compare("fin") == 0){
		tcp->fin = 1;
	}else

	// synchronize flag
	if(option.compare("syn") == 0){
		tcp->syn = 1;
	}else

	// reset flag
	if(option.compare("rst") == 0){
		tcp->rst = 1;
	}else

	// push flag
	if(option.compare("psh") == 0){
		tcp->psh = 1;
	}else

	// acknowledgement flag
	if(option.compare("ack") == 0){
		tcp->ack = 1;
	}else
	
	// urgent pointer flag
	if(option.compare("urg") == 0){
		tcp->urg = 1;
	}else

	// window size
	if(option.compare("window") == 0){
		uint16_t *window = (uint16_t *)val;
		tcp->window = htons(*window);
	}else

	// checksum
	if(option.compare("check") == 0){
		struct TCP_pseudo_t *ptr = (struct TCP_pseudo_t *)val;
		tcp->check = htons(tcpChecksome(ptr));
	}else
	
	// urgent sequence number
	if(option.compare("urg_ptr") == 0){
		uint16_t *urg_ptr = (uint16_t *)val;
		tcp->urg_ptr = htons(*urg_ptr);
	}else

		{
			LOG(ERROR, "Invalid Option TCP option :" + option);
			return false;
		}

	return true;
}


uint16_t PacketFactory::tcpChecksome(struct TCP_pseudo_t *ptr){
	uint16_t sum;
	
	sum = checksumCalculator(ptr, sizeof(struct TCP_pseudo_t), 0);
	sum = checksumCalculator(packet, sizeof(struct tcphdr), (uint16_t)~sum);
	
	return sum;
	
}
uint16_t PacketFactory::checksumCalculator (const void * addr, uint32_t len, uint16_t init) {
  uint32_t sum;
  const uint16_t * word;
  sum = init;
  word = (uint16_t *) addr;

  while (len >= 2) {
    sum += *(word++);
    len -= 2;
  }

  if (len > 0) {
    uint16_t tmp;

    *(uint8_t *)(&tmp) = *(uint8_t *)word;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ((uint16_t)~sum);
}


// get unused port 
uint16_t  PacketFactory::getUnusedPort(){
	
	int random;

	mLock.lock();
	srand (time(NULL));
	random = rand() % ( MIN_PORT + (MAX_PORT - MIN_PORT));
	
	if(portRange[random]){
		random++;
		if (random > MAX_PORT){
			random = MIN_PORT;
		}
	}
	portRange[random] = 1;
	mLock.unlock();
	return (uint16_t)random;
}

//free used port
void PacketFactory::freeUsedPort(uint16_t port){
	mLock.lock();
	portRange[(int)port] = 0;
	mLock.unlock();
}

