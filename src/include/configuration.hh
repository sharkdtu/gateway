#ifndef CONFIGURATION_HH
#define CONFIGURATION_HH 1

#include <string>
#include <utility>
#include <stdexcept>

#include <boost/noncopyable.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/property_tree/xml_parser.hpp>

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

void Configuration::init()
{
	namespace fs = boost::filesystem;
	namespace pt = boost::property_tree;
	
	fs::path p = fs::path(CONF_FILE);
	if(fs::exists(p))
	{
		pt::ptree root;
		pt::read_xml(CONF_FILE, root);
		timeout = root.get<int>("gateway.timeout");
		pt::ptree addr_groups = root.get_child("gateway.addr_groups");
		BOOST_FOREACH(pt::ptree::value_type& v, addr_groups)
		{
			std::string peer_ip = v.second.get<std::string>("peer_ip");
			std::string local_ip = v.second.get<std::string>("local_ip");
			std::string planetlab_ip = v.second.get<std::string>("planetlab_ip");
			std::string interface = v.second.get<std::string>("interface");
			std::string peer_mac = v.second.get<std::string>("peer_mac");
			peer_to_planetlab[peer_ip] = planetlab_ip;
			peer_to_eth[peer_ip] = std::make_pair(interface, peer_mac);
		}
	}
	else
	{
		throw std::runtime_error("Can not find " + CONF_FILE);
	}
}

Configuration* Configuration::theobject = new Configuration;

} //namespace rusv

#endif
