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
		pt::ptree if_info = root.get_child("gateway.if_info");
		BOOST_FOREACH(pt::ptree::value_type& v, if_info)
		{
			Ifinfo* ifinfo = new Ifinfo;
			ifinfo->ifname = v.second.get<string>("ifname");
			ifinfo->ifip = v.second.get<string>("ifip");
			ifinfo->peer_ip = v.second.get<string>("peer_ip");
			ifinfo->peer_mac = v.second.get<string>("peer_mac");
			ifinfo->planetlab_ip = v.second.get<string>("planetlab_ip");
			ifname_map[ifinfo->ifname] = ifinfo;
		}
	}
	else
	{
		throw runtime_error("Can not find " + CONF_FILE);
	}
}

} // namespace rusv
