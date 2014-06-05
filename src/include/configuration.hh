#ifndef CONFIGURATION_HH
#define CONFIGURATION_HH 1

#include <string>
#include <utility>

#include <boost/noncopyable.hpp>

#include "hash_map.hh"

namespace rusv
{

const std::string CONF_FILE = "conf/gateway.xml";

struct Ifinfo
{
	std::string ifname;
	std::string ifip;
	std::string peer_ip;
	std::string peer_mac;
	std::string planetlab_ip;
};

class Configuration : boost::noncopyable
{
public:
	static Configuration* instance()
	{
		return theobject;
	}

	bool has_ifname(const std::string& ifname)
	{
		if(ifname_map.find(ifname) != ifname_map.end())
			return true;
		else
			return false;
	}

	std::string get_peer_ip(const std::string& ifname)
	{
		return (ifname_map[ifname])->peer_ip;
	}

	std::string get_peer_mac(const std::string& ifname)
	{
		return (ifname_map[ifname])->peer_mac;
	}

	std::string get_ifip(const std::string& ifname)
	{
		return (ifname_map[ifname])->ifip;
	}

	std::string get_planetlab_ip(const std::string& ifname)
	{
		return (ifname_map[ifname])->planetlab_ip;
	}

	hash_map<std::string, Ifinfo*>
	get_ifname_map()
	{
		return ifname_map;
	}

private:
	Configuration()
	{
		init();
	}

	void init();

private:
	static Configuration* theobject;
	hash_map<std::string, Ifinfo*> ifname_map;
};

} //namespace rusv

#endif
