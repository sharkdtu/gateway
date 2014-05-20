#include "configuration.hh"

#include <stdexcept>

#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/property_tree/xml_parser.hpp>

using namespace std;

namespace rusv
{

Configuration* Configuration::theobject = new Configuration;

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
			string peer_ip = v.second.get<string>("peer_ip");
			string local_ip = v.second.get<string>("local_ip");
			string planetlab_ip = v.second.get<string>("planetlab_ip");
			string interface = v.second.get<string>("interface");
			string peer_mac = v.second.get<string>("peer_mac");
			peer_to_planetlab[peer_ip] = planetlab_ip;
			peer_to_eth[peer_ip] = make_pair(interface, peer_mac);
		}
	}
	else
	{
		throw runtime_error("Can not find " + CONF_FILE);
	}
}

} // namespace rusv
