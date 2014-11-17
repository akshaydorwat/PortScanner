/**
 * Author    : Akshay Dorwat
 * Date      : 11-14-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#include "SMTPvScan.hpp"

void SMTPvScan::createPacket(){
	LOG(WARNING, debugInfo + "Create packet method not implmeneted");
}


bool SMTPvScan::init(){
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
		LOG(DEBUG,debugInfo + "Socket Initialized");
	}
	
	// set timeout                                                                                       
	time_out.tv_sec = 3;
	time_out.tv_usec = 0;

	if(setsockopt(sfd,  SOL_SOCKET, SO_SNDTIMEO, &time_out, sizeof(struct timeval)) < 0){
		LOG(WARNING, debugInfo +  "Unable to set socket option SO_SNDTIMEO to False");
		return false;
	}else{
		LOG(DEBUG, debugInfo +  "send TIME OUT set");
	}

	if(setsockopt(sfd,  SOL_SOCKET, SO_RCVTIMEO, &time_out, sizeof(struct timeval)) < 0){
		LOG(WARNING, debugInfo + "Unable to set socket option SO_RCVTIMEO to False");
		return false;
	}else{
		LOG(DEBUG, debugInfo +  "recv TIME OUT set");
	}

	// host to network short
	unsigned short host_port = dst.sin_port;
	dst.sin_port = htons(host_port);

	// try to connect
	if((ret = connect(sfd, (struct sockaddr *)&dst, sizeof(dst))) == -1){
		LOG(WARNING, debugInfo + "Failed to connect ");
		return false;
	}
	return true;
}

bool SMTPvScan::send(){
	LOG(WARNING, debugInfo + "send method is not implemented");
	return true;
}

void SMTPvScan::handle(){

	int ret;
	char buff[BUFFER_SIZE];

	// Initialise the packet and socket
	if(!init()){
		LOG(WARNING, debugInfo + "POP init error");
		return;
	}
	
	// send packet and wait for the response
	for(int i=0 ; i < 1; i++){
		if((ret = read(sfd, buff , BUFFER_SIZE)) != -1){
			string version = getVersion(buff, ret);
			LOG(DEBUG, debugInfo + "POP : " + version);
			StatsReporter &stsRptr = StatsReporter::getStatsReporter();	
			stsRptr.updateServiceStatus(dst.sin_addr, ntohs(dst.sin_port), "", version);
			break;
		}
	}
}

string SMTPvScan::getVersion(const char* buff, int &ret){
	size_t start;
	size_t end;
	string s = string(buff, ret);

	const string temp = "220 mailserver.sample.com "; 
	const string temp2 = ";";
	if((start = s.find(temp)) != string::npos){
		if((end = s.find(temp2)) != string::npos){
			start += temp.length();
			return s.substr(start, end - start);
		}else{
			return "";
		}
	}else{
		return "";
	}
}

void SMTPvScan::filterCallback(const u_char *packet){
	LOG(WARNING, debugInfo + "This method is not implemented");
}


