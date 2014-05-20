#ifndef CONFIGURATION_HH
#define CONFIGURATION_HH 1

#include <string>
#include <utility>

#include <boost/noncopyable.hpp>

#include "hash_map.hh"

namespace rusv
{

const std::string CONF_FILE = "conf/gateway.xml";

class Configuration : boost::noncopyable
{
public:
	static Configuration* instance()
	{
		return theobject;
	}

	bool has_peer(std::string peer_ip)
	{
		if(peer_to_planetlab.find(peer_ip) != peer_to_planetlab.end())
			return true;
		else
			return false;
	}

	std::pair<std::string, std::string>
	get_eth(std::string peer_ip)
	{
		return peer_to_eth[peer_ip];
	}

	std::string get_planetlab_ip(std::string peer_ip)
	{
		return peer_to_planetlab[peer_ip];
	}

	hash_map<std::string, std::string>
	get_all_planetlab_ip()
	{
		return peer_to_planetlab;
	}

	int get_timeout()
	{
		return timeout;
	}

private:
	Configuration()
	{
		init();
	}

	void init();

private:
	static Configuration* theobject;
	hash_map<std::string, std::pair<std::string, std::string> > peer_to_eth;
	hash_map<std::string, std::string> peer_to_planetlab;
	int timeout;//unit(s)
};

} //namespace rusv

#endif
