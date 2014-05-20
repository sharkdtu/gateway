#include <string>

#include <boost/thread.hpp>

#include "hash_map.hh"

namespace rusv
{

const unsigned int BUFSIZE = 65535; 
const unsigned short int planetlab_port = 8888;

class Gateway 
{
public:
	Gateway();
	~Gateway();

	int connect_to_planetlab(std::string planetlab_ip);

	void from_router_to_planetlab();

	void from_planetlab_to_router(std::string planetlab_ip);

	void heartbeat(std::string planetlab_ip);

	void run();

private:
	hash_map<std::string, int> planetlab_to_sockfd;
	int raw_sockfd;
	boost::thread_group tg;
};

}// namespace rusv