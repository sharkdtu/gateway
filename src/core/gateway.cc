#include "gateway.hh"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/select.h>
#include <sys/time.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <utility>

#include <boost/bind.hpp>

#include "util.hh"
#include "vlog.hh"

using namespace std;

namespace rusv
{

static Vlog_module lg("gateway");

enum sock_t
{
	RAW,
	TCP
};

static int create_socket(sock_t st)
{
	int sockfd;
	switch(st)
	{
	case (RAW):
		sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
		break;
	case (TCP):
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		break;
	default:
		lg.err("socket type not supported");
		exit(EXIT_FAILURE);
	}
	if(sockfd < 0)
	{
		lg.err("create socket error");
		perror("socket error");
		exit(EXIT_FAILURE);
	}
	return sockfd;
}

static int recv_timeout(int sockfd, int sec)
{
	fd_set rset;
	struct timeval tv;

	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);

	tv.tv_sec = sec;
	tv.tv_usec = 0;

	return (select(sockfd+1, &rset, NULL, NULL, &tv));
}

Gateway::Gateway() : conf(Configuration::instance())
{
	raw_sockfd = create_socket(RAW);
	int size = 60 * 1024;
	if(setsockopt(raw_sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0)
	{
		lg.err("setsockopt error on raw_sockfd");
		perror("setsockopt error");
		exit(EXIT_FAILURE);
	}

	hash_map<string, string> peer_to_planetlab = conf->get_all_planetlab_ip();
	hash_map<string, string>::iterator it = peer_to_planetlab.begin();
	for(; it != peer_to_planetlab.end(); it++)
	{
		string planetlab_ip = it->second;
		if(planetlab_to_sockfd.find(planetlab_ip) != planetlab_to_sockfd.end())
			continue;

		int tcp_sockfd = create_socket(TCP);
		planetlab_to_sockfd[planetlab_ip] = tcp_sockfd;

		// attempt to connect to planetlab
		if(connect_to_planetlab(planetlab_ip) < 0)
		{
			lg.err("connect planetlab(%s) error", planetlab_ip.c_str());
			perror("connect error");
		}
		else
		{
			lg.dbg("connect to planetlab(%s) successed", planetlab_ip.c_str());
		}

		tg.create_thread(boost::bind(&Gateway::heartbeat, this, planetlab_ip));
		tg.create_thread(boost::bind(&Gateway::from_planetlab_to_router, this, planetlab_ip));
	}

	tg.create_thread(boost::bind(&Gateway::from_router_to_planetlab, this));
}

Gateway::~Gateway()
{
}

int Gateway::connect_to_planetlab(string planetlab_ip)
{
	int tcp_sockfd = planetlab_to_sockfd[planetlab_ip];

	struct sockaddr_in to;
	bzero(&to, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_port = htons(planetlab_port);
	if(inet_aton(planetlab_ip.c_str(), &to.sin_addr) < 0)
	{
		lg.err("inet_pton error for %s", planetlab_ip.c_str());
		perror("inet_pton error");
		exit(EXIT_FAILURE);
	}

	return connect(tcp_sockfd, (struct sockaddr*)&to, sizeof(to));
}

void Gateway::from_router_to_planetlab()
{
	char buffer[BUFSIZE];
	for(; ;)
	{
		int bytes_received;
		if((bytes_received = recvfrom(raw_sockfd, buffer, sizeof(buffer), 0, NULL, NULL)) < 0)
		{
			lg.err("recvfrom error on raw_sockfd");
			perror("recvfrom error");
		}
		else
		{
			struct ip* iphdr = (struct ip*)buffer;
			string peer_ip ((char*)inet_ntoa(iphdr->ip_src));
			if(!conf->has_peer(peer_ip))
				//ignore packet from planetlab
				continue;
			lg.dbg("receive ip packet from %s", peer_ip.c_str());

			string planetlab_ip = conf->get_planetlab_ip(peer_ip);
			int tcp_sockfd = planetlab_to_sockfd[planetlab_ip];
			if(send(tcp_sockfd, buffer, bytes_received, 0) < 0)
			{
				lg.err("send packet to planetlab(%s) failed", planetlab_ip.c_str());
				perror("send error");
			}
			else
			{
				lg.dbg("send packet to planetlab(%s) successed.", planetlab_ip.c_str());
			}
		}
	}
}

void Gateway::from_planetlab_to_router(string planetlab_ip)
{
	int tcp_sockfd = planetlab_to_sockfd[planetlab_ip];
	int sockfd = create_socket(RAW);

	for(; ;)
	{
		char buffer[BUFSIZE];
		int bytes_received;
		if((bytes_received = recv(tcp_sockfd, buffer, sizeof(buffer), 0)) < 0)
		{
			lg.err("receive packet from %s error", planetlab_ip.c_str());
			perror("recv error");
		}
		else
		{
			// ignore hello packet
			if(buffer[0] == 'h')
				continue;

			struct ip* iphdr = (struct ip*) buffer;
			string peer_ip((char*)inet_ntoa(iphdr->ip_dst));
			if(!conf->has_peer(peer_ip))
				continue;
			lg.dbg("receive ip packet from %s", planetlab_ip.c_str());

			unsigned char peer_mac[ETH_ALEN];
			pair<string, string> eth = conf->get_eth(peer_ip);
			if(str_to_mac(eth.second, peer_mac) < 0)
			{
				lg.err("convert mac(%s) error", eth.second.c_str());
				continue;
			}
			struct ifreq ifstruct;
			strcpy(ifstruct.ifr_name, eth.first.c_str());
			if(ioctl(sockfd, SIOCGIFINDEX, &ifstruct) < 0) {
				lg.err("ioctl error on sockfd");
				perror("ioctl error");
				exit(EXIT_FAILURE);
			}

			struct sockaddr_ll to;
			bzero(&to, sizeof(to));
			to.sll_family = PF_PACKET;
			to.sll_protocol = htons(ETH_P_IP);
			to.sll_halen = ETH_ALEN;
			memcpy(to.sll_addr, peer_mac, ETH_ALEN);
			to.sll_ifindex = ifstruct.ifr_ifindex;

			if(sendto(sockfd, buffer, bytes_received, 0, (struct sockaddr*)&to, sizeof(to)) < 0)
			{
				lg.err("send packet to router(%s) failed", eth.second.c_str());
				perror("sendto error");
			}
			else
			{
				lg.dbg("send packet to router(%s) successed", eth.second.c_str());
			}
		}
	}
}

void Gateway::heartbeat(string planetlab_ip)
{
	int tcp_sockfd = planetlab_to_sockfd[planetlab_ip];
	char hello[10] = "hello";
	for(; ;)
	{
		if(send(tcp_sockfd, hello, strlen(hello)+1, 0) < 0)
		{
			lg.err("send hello to planetlab(%s) failed", planetlab_ip.c_str());
			perror("send error");
			close(tcp_sockfd);
			tcp_sockfd = create_socket(TCP);
			planetlab_to_sockfd[planetlab_ip] = tcp_sockfd;

			int times = 0;
			while(connect_to_planetlab(planetlab_ip) < 0)
			{
				times++;
				lg.err("connect planetlab(%s) error %d times", planetlab_ip.c_str(), times);
				perror("connect error");
				sleep(3);
			}
			continue;
		}
		
		int timeout = conf->get_timeout();
		if(recv_timeout(tcp_sockfd, timeout) == 0)
		{
			lg.err("receive hello timeout");
			close(tcp_sockfd);
			tcp_sockfd = create_socket(TCP);
			planetlab_to_sockfd[planetlab_ip] = tcp_sockfd;

			int times = 0;
			while(connect_to_planetlab(planetlab_ip) < 0)
			{
				times++;
				lg.err("connect planetlab(%s) error %d times", planetlab_ip.c_str(), times);
				perror("connect error");
				sleep(3);
			}
		}

		sleep(60);
	}
}

void Gateway::run()
{
	tg.join_all();
}

} // namespace rusv
