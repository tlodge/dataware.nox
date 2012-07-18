/* Copyright 2008 (C) Nicira, Inc.
 * Copyright 2009 (C) Stanford University.
 *
 * This file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef MONITORSWITCH_HH
#define MONITORSWITCH_HH
#include <map>


#include "openflow-default.hh"
#include "assert.hh"
#include "component.hh"
#include "flow.hh"
#include "fnv_hash.hh"
#include "hash_set.hh"
#include "packet-in.hh"
#include "config.h"
#include "control.hh"
#include "dhcp_msg.hh"
#include "string"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

//#include <linux/netlink.h> 
//#include <linux/pkt_sched.h>

#include <sys/ioctl.h>
#include <net/if.h>


#include <netinet++/ip.hh>
#include <netinet++/cidr.hh>

#include <boost/shared_ptr.hpp>

#define TIMELEN 20
#define RECORDLEN 255

namespace vigil
{
			
	using namespace std;
	using namespace vigil::container;

	 struct nw_hdr {
        struct ether_header *ether;
        struct iphdr *ip;
        union {
            struct udphdr *udp;
            struct tcphdr *tcp;
            struct igmphdr *igmp;
        };
        uint8_t *data;
    };
    
	class MonitorSwitch
    : public Component 
	{
		public:
			
			MonitorSwitch(const Context* c, const json_object*) : Component(c) { }

			void configure(const Configuration*);

			void install();
			
			

			Disposition handle(const Event&);
 			Disposition datapath_join_handler(const Event& e);
            Disposition datapath_leave_handler(const Event& e);
            
            
		    static void getInstance(const container::Context* c,
                    MonitorSwitch*& component);

		private:
		
		 	bool send_flow_modification (Flow fl, uint32_t wildcard, datapathid datapath_id,
                    uint32_t buffer_id, uint16_t command,
                    uint16_t idle_timeout, uint16_t prio,
                    std::vector<boost::shared_array<char> > act);
        	
        	//datapath storage
            std::vector<datapathid*> registered_datapath;
            
			void recordDHCP(Flow flow, const Packet_in_event& pi);
		
			void recordDNS(Flow flow, const Packet_in_event& pi);
			
			void addDHCPRecord(const char *action, const char *ip, const char *mac, const char *hostname);
			
			void addDNSRecord(const char* tstamp, const char *mac, const char *ip, const char *url);
			
			void fromDNSNameFormat(string& question);
			
			bool duplicate(const char* time, const char* url);
			
			bool extract_headers(uint8_t *, uint32_t, struct nw_hdr *);
			
			HWDBControl *hwdb;
			//netlink control
            struct nl_sock *sk;        //the socket to talk to netlink
            
            int ifindex;               //index of the interface.
            
         
            char lasttime[TIMELEN];
            char lastrecord[RECORDLEN];
            
			ethernetaddr bridge_mac;
	};
}

#endif
