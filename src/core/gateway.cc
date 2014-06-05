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
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <utility>

#include <boost/bind.hpp>
#include <boost/assign.hpp>

#include "util.hh"
#include "vlog.hh"
#include "timeval.hh"

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
	int sockfd = -1;
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
		lg.err("socket error(%s)", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

static void make_sockfd_non_block(int sockfd)
{
	int flags = fcntl(sockfd, F_GETFL, 0);
	if(flags < 0)
	{
		lg.err("fcntl error(%s)", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if(fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0)
	{
		lg.err("fcntl error(%s)", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

/*
static int recv_timeout(int sockfd, void* buf, size_t len, int nsec)
{
	fd_set rset;
	struct timeval tv;

	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);

	tv.tv_sec = nsec;
	tv.tv_usec = 0;

	int n = select(sockfd+1, &rset, NULL, NULL, nsec ? &tv : NULL);
	if (0 == n)
	{
		errno = ETIMEDOUT;
		return -1;
	} 
	else if(n < 0 || !FD_ISSET(sockfd, &rset))
	{
		return -1;
	}
	else
	{
		return recv(sockfd, buf, len, 0);
	}
}*/


static int connect_timeout(int sockfd, const struct sockaddr* saptr, 
		socklen_t salen, int nsec)
{
	fd_set rset, wset;
	struct timeval tv;

	int n = connect(sockfd, saptr, salen);

	if(n < 0)
	{
		if(errno != EINPROGRESS)
			return -1;

		FD_ZERO(&rset);
		FD_SET(sockfd, &rset);
		wset = rset;
		tv.tv_sec = nsec;
		tv.tv_usec = 0;
		n = select(sockfd + 1, &rset, &wset, NULL, nsec ? &tv : NULL);
		if(0 == n) 
		{
			errno = ETIMEDOUT;
			return -1;
		}
		else if(n < 0)
			return -1;
		else if(!FD_ISSET(sockfd, &rset) && FD_ISSET(sockfd, &wset)) 
			return 0;
		else
			return -1;
	}
	else
		return 0;

}

static int get_iface_index(int fd, const char* ifname)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strcpy (ifr.ifr_name, ifname);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
	{
		lg.err("ioctl get_if_index error(%s)", strerror(errno));
		exit(EXIT_FAILURE);
	}
	return ifr.ifr_ifindex;
}

/*
static string get_iface_name(int fd, int ifindex)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ifindex;
	if (ioctl(fd, SIOCGIFNAME, &ifr) < 0)
	{
		lg.err("ioctl get_if_index error(%s)", strerror(errno));
		exit(EXIT_FAILURE);
	}
	return string(ifr.ifr_name);
}*/

static int send_non_block(int sockfd, void* buffer, size_t len)
{
	fd_set wset;
	FD_ZERO(&wset);
	FD_SET(sockfd, &wset);
	if(select(sockfd+1, NULL, &wset, NULL, NULL) < 0)
		return -1;
	if(send(sockfd, buffer, len, MSG_NOSIGNAL) < 0)
		return -1;
	return 0;
}

Gateway::Gateway() : conf(Configuration::instance())
{
//	int size = 60 * 1024;
//	if(setsockopt(raw_sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0)
//	{
//		lg.err("setsockopt error on raw_sockfd");
//		lg.err("fcntl error(%s)", strerror(errno));
//		perror("setsockopt error");
//		exit(EXIT_FAILURE);
//	}

	hash_map<string, Ifinfo*> ifname_map = conf->get_ifname_map();
	hash_map<string, Ifinfo*>::iterator it = ifname_map.begin();
	for(; it != ifname_map.end(); it++)
	{
		string ifname = it->first;
		string planetlab_ip = it->second->planetlab_ip;

		if(ifname_to_rawfd.find(ifname) == ifname_to_rawfd.end())
		{
			int raw_sockfd = create_socket(RAW);
			make_sockfd_non_block(raw_sockfd);
			ifname_to_rawfd[ifname] = raw_sockfd;
		}

		if(ifname_to_tcpfd.find(ifname) == ifname_to_tcpfd.end())
		{
			int tcp_sockfd = create_socket(TCP);
			make_sockfd_non_block(tcp_sockfd);
			ifname_to_tcpfd[ifname] = tcp_sockfd;
			// attempt to connect to planetlab
			lg.info("connecting to planetlab(%s)...", planetlab_ip.c_str());
			if(connect_to_planetlab(tcp_sockfd, planetlab_ip) < 0)
				lg.err("connect planetlab(%s) error", planetlab_ip.c_str());
			else
				lg.info("connect to planetlab(%s) successed", planetlab_ip.c_str());
		}

		tg.create_thread(boost::bind(&Gateway::from_router_to_planetlab, this, ifname));
		lg.info("create thread for sending ip packet from %s to planetlab(%s)", ifname.c_str(), planetlab_ip.c_str());
		tg.create_thread(boost::bind(&Gateway::from_planetlab_to_router, this, ifname));
		lg.info("create thread for sending ip packet from planetlab(%s) to %s", planetlab_ip.c_str(), ifname.c_str());
	}
}

Gateway::~Gateway()
{
}

Pkt_header* Gateway::make_hello_packet(const string& ifname)
{
	Pkt_header* hello = new Pkt_header;
	hello->version = 1;
	hello->type = HELLO;
	hello->datalen = 0;
	if(inet_aton(conf->get_peer_ip(ifname).c_str(), &hello->src_ip) < 0)
	{
		lg.err("inet_aton error(%s)", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if(inet_aton(conf->get_ifip(ifname).c_str(), &hello->dst_ip) < 0)
	{
		lg.err("inet_aton error(%s)", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return hello;
}

Pkt_header* Gateway::make_data_packet(const string& ifname, void* buffer, int len)
{
	char* pkt = (char*)malloc(sizeof(Pkt_header) + len);
	Pkt_header* pkthdr = (Pkt_header*)pkt;
	pkthdr->version = 1;
	pkthdr->type = IP;
	pkthdr->datalen = len;
	if(inet_aton(conf->get_peer_ip(ifname).c_str(), &pkthdr->src_ip) < 0)
	{
		lg.err("inet_aton error(%s)", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if(inet_aton(conf->get_ifip(ifname).c_str(), &pkthdr->dst_ip) < 0)
	{
		lg.err("inet_aton error(%s)", strerror(errno));
		exit(EXIT_FAILURE);
	}

	memcpy(pkt+sizeof(Pkt_header), buffer, len);

	return (Pkt_header*)pkt;
}

int Gateway::connect_to_planetlab(int sockfd, const string& planetlab_ip)
{
	struct sockaddr_in to;
	bzero(&to, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_port = htons(planetlab_port);
	if(inet_aton(planetlab_ip.c_str(), &to.sin_addr) < 0)
	{
		lg.err("inet_pton error(%s)", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return connect_timeout(sockfd, (struct sockaddr*)&to, sizeof(to), CONN_TIMEOUT);
}

void Gateway::from_router_to_planetlab(const string& ifname)
{
	int raw_sockfd = ifname_to_rawfd[ifname];
	int tcp_sockfd = ifname_to_tcpfd[ifname];
	string planetlab_ip = conf->get_planetlab_ip(ifname);

	struct sockaddr_ll sa;
	bzero(&sa, sizeof(sa));
	sa.sll_family = PF_PACKET;
	sa.sll_protocol = htons(ETH_P_IP);
	sa.sll_ifindex = get_iface_index(raw_sockfd, ifname.c_str());

	if(::bind(raw_sockfd, (struct sockaddr*)&sa, sizeof(sa)) < 0)
	{
		lg.err("bind raw_sockfd error(%s)", strerror(errno));
		exit(EXIT_FAILURE);
	}

	Pkt_header* hello = make_hello_packet(ifname);
	while(send_non_block(tcp_sockfd, hello, sizeof(Pkt_header)) < 0)
	{
		lg.err("send hello to planetlab(%s) error(%s)", 
				planetlab_ip.c_str(), strerror(errno));
		sleep(HEARTBEAT_INTERVAL);
		tcp_sockfd = ifname_to_tcpfd[ifname];
	}
	lg.dbg("send hello to planetlab(%s) successed", planetlab_ip.c_str());
	long long int hello_timestamp = time_msec();

	char buffer[BUFSIZE];
	for(; ;)
	{
		tcp_sockfd = ifname_to_tcpfd[ifname];
		if(tcp_sockfd <= 0)
		{
			lg.err("connection to %s error", planetlab_ip.c_str());
			continue;
		}

		struct timeval tv;
		tv.tv_sec = HEARTBEAT_INTERVAL;
		tv.tv_usec = 0;

		fd_set rset;
		FD_ZERO(&rset);
		FD_SET(raw_sockfd, &rset);

		int n = select(raw_sockfd+1, &rset, NULL, NULL, &tv);
		if(n == 0) 
		{
			//no data, send hello.
			if(send_non_block(tcp_sockfd, hello, sizeof(Pkt_header)) < 0)
			{
				lg.err("send hello to planetlab(%s) error(%s)", planetlab_ip.c_str(), strerror(errno));
				continue;
			}
			else 
			{
				lg.dbg("send hello to planetlab(%s) successed", planetlab_ip.c_str());
				hello_timestamp = time_msec();
			}
		}
		else if(n < 0)
		{
			lg.err("planetlab(%s) select error(%s)", planetlab_ip.c_str(), strerror(errno));
		}
		else if(FD_ISSET(raw_sockfd, &rset))
		{
			while(1)
			{
				long long int cur_time = time_msec();
				if(cur_time - hello_timestamp >= HEARTBEAT_INTERVAL*1000)
				{
					if(send_non_block(tcp_sockfd, hello, sizeof(Pkt_header)) < 0)
					{
						lg.err("send hello to planetlab(%s) error(%s)", planetlab_ip.c_str(), strerror(errno));
					}
					else 
					{
						lg.dbg("send hello to planetlab(%s) successed", planetlab_ip.c_str());
						hello_timestamp = time_msec();
					}
				}

				int bytes_received = recvfrom(raw_sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
				if(bytes_received < 0)
				{
					if(errno != EAGAIN && errno != EWOULDBLOCK)
						lg.err("recvfrom() for planetlab(%s) error(%s)", planetlab_ip.c_str(), strerror(errno));
					break;
				}
				else
				{
					Pkt_header* data = make_data_packet(ifname, buffer, bytes_received);
					if(send_non_block(tcp_sockfd, data, sizeof(Pkt_header)+bytes_received) < 0)
						lg.err("send data to planetlab(%s) error(%s)", planetlab_ip.c_str(), strerror(errno));
					else
						lg.dbg("send %d bytes data to planetlab(%s) successed", bytes_received, planetlab_ip.c_str());

					free(data);
				}
			}
		}
	}
}

void Gateway::from_planetlab_to_router(const string& ifname)
{
	int raw_sockfd = ifname_to_rawfd[ifname];
	string planetlab_ip = conf->get_planetlab_ip(ifname);

	for(; ;)
	{
		int tcp_sockfd = ifname_to_tcpfd[ifname];

		struct timeval tv;
		tv.tv_sec = 2*HEARTBEAT_INTERVAL;
		tv.tv_usec = 0;

		fd_set rset;
		FD_ZERO(&rset);
		FD_SET(tcp_sockfd, &rset);

		int n = select(tcp_sockfd+1, &rset, NULL, NULL, &tv);
		if(n == 0) 
		{
			lg.err("recv from planetlab(%s) timeout", planetlab_ip.c_str());

			close(tcp_sockfd);
			tcp_sockfd = create_socket(TCP);
			ifname_to_tcpfd[ifname] = tcp_sockfd;

			lg.dbg("attempt to connect to planetlab(%s)", planetlab_ip.c_str());
			int times = 0;
			while(connect_to_planetlab(tcp_sockfd, planetlab_ip) < 0)
			{
				times++;
				lg.err("connect planetlab(%s) error(%s) %d times", planetlab_ip.c_str(), strerror(errno), times);
				sleep(5);
			}

			lg.dbg("connect to planetlab(%s) successed", planetlab_ip.c_str());
		}
		else if(n < 0)
		{
			lg.err("planetlab(%s) select error(%s)", planetlab_ip.c_str(), strerror(errno));
		}
		else if(FD_ISSET(tcp_sockfd, &rset))
		{
			unsigned char peer_mac[ETH_ALEN];
			string str_peer_mac = conf->get_peer_mac(ifname);
			if(str_to_mac(str_peer_mac, peer_mac) < 0)
			{
				lg.err("convert mac(%s) error", str_peer_mac.c_str());
				break;
			}
			struct sockaddr_ll to;
			bzero(&to, sizeof(to));
			to.sll_family = AF_PACKET;
			to.sll_protocol = htons(ETH_P_IP);
		//	to.sll_pkttype = PACKET_HOST;
		//	to.sll_hatype = ARPHRD_ETHER;
			to.sll_ifindex = get_iface_index(raw_sockfd, ifname.c_str());
			to.sll_halen = ETH_ALEN;
			memcpy(to.sll_addr, peer_mac, ETH_ALEN);
		
		//	lg.dbg("%s", mac_to_str(peer_mac).c_str());
		//	lg.dbg("address len: %d", sizeof(to));

			Pkt_header* pkthdr = new Pkt_header;
			while(1)
			{
				int bytes_received = recv(tcp_sockfd, pkthdr, sizeof(Pkt_header), 0);
				if(bytes_received <= 0)
				{
					if (errno != EAGAIN && errno != EWOULDBLOCK)
					{
						lg.err("recv from planetlab(%s) error(%s)", planetlab_ip.c_str(), strerror(errno));

						close(tcp_sockfd);
						tcp_sockfd = create_socket(TCP);
						ifname_to_tcpfd[ifname] = tcp_sockfd;

						lg.dbg("attempt to connect to planetlab(%s)", planetlab_ip.c_str());

						int times = 0;
						while(connect_to_planetlab(tcp_sockfd, planetlab_ip) < 0)
						{
							times++;
							lg.err("connect planetlab(%s) error(%s) %d times", planetlab_ip.c_str(), strerror(errno), times);
							sleep(5);
						}

						lg.dbg("connect to planetlab(%s) successed", planetlab_ip.c_str());
					}
					
					break;
				}
				else
				{
					if(bytes_received < sizeof(Pkt_header))
					{
						lg.err("recv from planetlab(%s) data error", planetlab_ip.c_str());
						break;
					}

					if(pkthdr->type == HELLO)
					{
						lg.dbg("recv hello from planetlab(%s) successed", planetlab_ip.c_str());
						continue;
					}

					int bytes_tosend = pkthdr->datalen;

					char* tosend = (char*)malloc(bytes_tosend);
					if(recv(tcp_sockfd, tosend, bytes_tosend, 0) < bytes_tosend)
					{
						lg.err("recv from planetlab(%s) data error", planetlab_ip.c_str());
						continue;
					}

					lg.dbg("recv %d bytes data from planetlab(%s)", bytes_tosend, planetlab_ip.c_str());

					if(sendto(raw_sockfd, tosend, bytes_tosend, 0, (struct sockaddr*)&to, sizeof(to)) < 0)
						lg.err("send ip packet to %s error(%s)", conf->get_peer_ip(ifname).c_str(), strerror(errno));
					else
						lg.dbg("send ip packet %d bytes to %s successed", bytes_tosend, conf->get_peer_ip(ifname).c_str());

					free(tosend);
				}
			}

			delete pkthdr;
		}
	}
}

void Gateway::run()
{
	tg.join_all();
}

} // namespace rusv
