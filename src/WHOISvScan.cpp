/**
 * Author    : Akshay Dorwat
 * Date      : 11-14-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#include "WHOISvScan.hpp"

void WHOISvScan::createPacket(){
	const char *query ="google.com\r\n\0";
	memcpy(buff, query,strlen(query));
	packetLen = strlen(buff);
}


bool WHOISvScan::init(){
	int ret;
	struct timeval time_out;
	
	// create packet 
	createPacket();

	// create raw socket
	sfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sfd < 0 ){
		LOG(WARNING,"Failed to create TCP socket");
		return false;
	}else{
		LOG(DEBUG,"Socket Initialized");
	}
	
	// set timeout                                                                                       
	time_out.tv_sec = 3;
	time_out.tv_usec = 0;


	if(setsockopt(sfd,  SOL_SOCKET, SO_SNDTIMEO, &time_out, sizeof(struct timeval)) < 0){
		LOG(ERROR, "Unable to set socket option SO_SNDTIMEO to Flase");
		return false;
	}else{
		LOG(DEBUG, "send TIME OUT set");
	}

	if(setsockopt(sfd,  SOL_SOCKET, SO_RCVTIMEO, &time_out, sizeof(struct timeval)) < 0){
		LOG(ERROR, "Unable to set socket option SO_RCVTIMEO to Flase");
		return false;
	}else{
		LOG(DEBUG, "send TIME OUT set");
	}

	// host to network short
	unsigned short host_port = dst.sin_port;
	dst.sin_port = htons(host_port);

	// try to connect
	if((ret = connect(sfd, (struct sockaddr *)&dst, sizeof(dst))) == -1){
		LOG(ERROR, "Failed to connect ");
		return false;
	}
	return true;
}

bool WHOISvScan::send(){
	int ret;
	if((ret = sendto(sfd, buff, packetLen, MSG_DONTWAIT, NULL, 0)) == -1){
		LOG(ERROR, debugInfo + " failed to write data");
		return false;
	}else{
		LOG(DEBUG, debugInfo + " packet sent successfully");
		numOfPacketSent++;
	}
	return true;
}

void WHOISvScan::handle(){

	int ret;
	char buff[BUFFER_SIZE];

	// Initialise the packet and socket
	if(!init()){
		LOG(ERROR, debugInfo + " WHOIS init error");
		return;
	}
	
	// send packet and wait for the response
	for(int i=0 ; i < 1; i++){
		if(send()){
			if((ret = read(sfd, buff , BUFFER_SIZE)) != -1){
				string s = getVersion(buff, ret);
				LOG(DEBUG, debugInfo + "WHOIS : " + s);
				break;
			}
		}
	}
}

string WHOISvScan::getVersion(const char* buff, int &ret){
	size_t start;
	size_t end;
	string s = string(buff, ret);

	const string temp = "Whois Server Version "; 
	if((start = s.find(temp)) != string::npos){
		if((end = s.find("\n", temp.length()+1)) != string::npos){
			return s.substr(start, end - start);
		}else{
			return "";
		}
	}else{
		return "";
	}
}

void WHOISvScan::filterCallback(const u_char *packet){
	LOG(WARNING, debugInfo + " This method is not implemented");
}


