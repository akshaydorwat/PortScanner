/**
 * Author    : Akshay Dorwat
 * Date      : 11-14-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#include "SSHvScan.hpp"

void SSHvScan::createPacket(){
	LOG(WARNING, debugInfo + "Create packet method not implmeneted");
}


bool SSHvScan::init(){
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

bool SSHvScan::send(){
	LOG(WARNING, debugInfo + "send method is not implemented");
	return true;
}

void SSHvScan::handle(){

	int ret;
	char buff[BUFFER_SIZE];
	bool flag = false;
	string version;

	// Initialise the packet and socket
	if(!init()){
		LOG(WARNING, debugInfo + "SSH init error");
		return;
	}
	
	// send packet and wait for the response
	for(int i=0 ; i < 1; i++){
		if((ret = read(sfd, buff , BUFFER_SIZE)) != -1){
			version = getVersion(buff, ret);
			LOG(DEBUG, debugInfo + "SSH : " + version);
			flag = true;
			break;
		}
	}

	StatsReporter &stsRptr = StatsReporter::getStatsReporter();

	if(flag){
		stsRptr.updateServiceStatus(dst.sin_addr, ntohs(dst.sin_port), "", version);
	}else{
		stsRptr.updateServiceStatus(dst.sin_addr, ntohs(dst.sin_port), "", "");
	}
}

string SSHvScan::getVersion(const char* buff, int &ret){
	size_t start;
	size_t end;
	string s = string(buff, ret);

	const string temp = "SSH-"; 
	if((start = s.find(temp)) != string::npos){
		if((end = s.find("-", temp.length()+1)) != string::npos){
			start += temp.length();
			return s.substr(start, end - start);
		}else{
			return "";
		}
	}else{
		return "";
	}
}

void SSHvScan::filterCallback(const u_char *packet){
	LOG(WARNING, debugInfo + "This method is not implemented");
}
