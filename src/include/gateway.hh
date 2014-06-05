#include <netinet/in.h>

#include <string>

#include <boost/thread.hpp>

#include "hash_map.hh"
#include "configuration.hh"

namespace rusv
{

const unsigned int BUFSIZE = 1024; 
const unsigned int CONN_TIMEOUT = 10;
const unsigned int HEARTBEAT_INTERVAL = 10;

const unsigned short int planetlab_port = 48888;

struct Pkt_header
{
        uint8_t version;
        uint8_t type;
        uint16_t datalen;
        struct in_addr src_ip, dst_ip;
};

enum Pkt_type
{
        HELLO,
        IP      
};

class Gateway 
{
public:
	Gateway();
	~Gateway();

	int connect_to_planetlab(int sockfd, const std::string& planetlab_ip);

	void from_router_to_planetlab(const std::string& ifname);

	void from_planetlab_to_router(const std::string& ifname);

	Pkt_header* make_hello_packet(const std::string& ifname);

	Pkt_header* make_data_packet(const std::string& ifname, void* buffer, int len);

	void run();

private:
	hash_map<std::string, int> ifname_to_rawfd;
	hash_map<std::string, int> ifname_to_tcpfd;

	Configuration* conf; //the conf singleton
	boost::thread_group tg;
};

}// namespace rusv
