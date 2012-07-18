/* Copyright 2008 (C) Nicira, Inc.
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
#include "monitorswitch.hh"
#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#include <boost/shared_array.hpp>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <stdint.h>


#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "packet-in.hh"
#include "netinet++/ethernet.hh"
#include "netinet++/ip.hh"
#include "netinet++/ipaddr.hh"

#define BRIDGE_INTERFACE_NAME "br0"

namespace vigil {

Vlog_module log("monitorswitch");

void 
MonitorSwitch::configure(const Configuration* conf) {
    
    register_handler<Packet_in_event>
        (boost::bind(&MonitorSwitch::handle, this, _1));

}

void
MonitorSwitch::install() {
 	resolve(hwdb);
 	unsigned char addr[ETH_ALEN];
	int s;
	struct ifreq ifr;
	memset(lasttime, '\0', TIMELEN);
	memset(lastrecord, '\0', RECORDLEN);
	
	register_handler<Packet_in_event>(boost::bind(&MonitorSwitch::handle, this, _1));
    
    register_handler<Datapath_join_event>(boost::bind(&MonitorSwitch::datapath_join_handler, 
                    this, _1));
                    
	register_handler<Datapath_leave_event>(boost::bind(&MonitorSwitch::datapath_leave_handler, 
                    this, _1));
	
	s = socket(AF_INET, SOCK_DGRAM, 0);
	
	if (s==-1) {
		log.err("Failed to open socket");
		exit(1);
	}

	ifr.ifr_addr.sa_family = AF_INET;
	
	strncpy(ifr.ifr_name, BRIDGE_INTERFACE_NAME, sizeof(BRIDGE_INTERFACE_NAME));

	if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
		log.err("Failed to get mac address");
		exit(1);
	}
	
	memcpy(addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	this->bridge_mac = ethernetaddr(addr);
	log.info("br0 mac addr : %s", this->bridge_mac.string().c_str());
	close(s);

}

void MonitorSwitch::getInstance(const Context* c,
            MonitorSwitch*& component) {
        component = dynamic_cast<MonitorSwitch*>
            (c->get_by_interface(container::Interface_description
                                 (typeid(MonitorSwitch).name())));
}


void MonitorSwitch::recordDNS(Flow flow, const Packet_in_event& pi){
	
	tstamp_t now  = timestamp_now();
	char *timestring = timestamp_to_datestring(now);
	
	uint8_t *data = pi.get_buffer()->data();
	int32_t data_len = pi.get_buffer()->size();
    
    int pointer = 0;

    //remove extra headers from data section of packet
	struct nw_hdr hdr;
        
    if(!this->extract_headers(data, data_len, &hdr)) {
    	log.err("malformed dns request packet");
    }
	
    
    char srcmac[18];

    sprintf(srcmac, "%02x:%02x:%02x:%02x:%02x:%02x", 
		hdr.ether->ether_shost[0] & 0xff,
		hdr.ether->ether_shost[1] & 0xff,
		hdr.ether->ether_shost[2] & 0xff,
		hdr.ether->ether_shost[3] & 0xff,
		hdr.ether->ether_shost[4] & 0xff,
		hdr.ether->ether_shost[5] & 0xff);
     
   
    struct in_addr sip;
    sip.s_addr = hdr.ip->saddr;
 
    uint16_t dns_len = ntohs(hdr.udp->len) - sizeof(struct udphdr);

    pointer = (hdr.data - data);
    
    
    data_len -= (hdr.data - data);
    
    struct dns_hdr *dns = (struct dns_hdr  *)hdr.data;
    
    data_len -= sizeof(struct dns_hdr);
    
	pointer +=  sizeof(struct dns_hdr);
    
    unsigned char *question[data_len+1];
    memset(question, '\0', data_len+1);
     
    memcpy(question, (data + pointer), data_len);
    string dnsname((char*) question);
   
    this->fromDNSNameFormat(dnsname);
    
    if (!duplicate(timestring, dnsname.c_str()))
      this->addDNSRecord(timestring, srcmac, inet_ntoa(sip),  dnsname.c_str());
}

bool MonitorSwitch::duplicate(const char* time,  const char* url){
   
    bool result;
    
    if (strcmp(time, lasttime) == 0 && strcmp(lastrecord, url) == 0){
        result = true;   
    }else{
        result = false;
        memset(lasttime, '\0', TIMELEN);
	    memset(lastrecord, '\0', RECORDLEN);
	    memcpy(lasttime, time, strlen(time));
	    memcpy(lastrecord, url, strlen(url));   
	}
	
    return result;
}

void MonitorSwitch::recordDHCP(Flow flow, const Packet_in_event& pi){
 		boost::shared_array<char> buf;	
		
        uint8_t *data = pi.get_buffer()->data();
        
        int32_t data_len = pi.get_buffer()->size();
        
        int pointer = 0;
        
        char *hostname = NULL;

        //remove extra headers from data section of packet
        struct nw_hdr hdr;
        if(!this->extract_headers(data, data_len, &hdr)) {
            log.err("malformed dhcp packet");
        }

        //calculate the dhcp packet len from the udp len field
        uint16_t dhcp_len = ntohs(hdr.udp->len) - sizeof(struct udphdr);

        pointer = (hdr.data - data);
        data_len -= (hdr.data - data);
		
        //extract the options of the packet
        struct dhcp_packet *dhcp = (struct dhcp_packet  *)hdr.data;
	
	    //analyse options and reply respectively.
        data_len -= sizeof(struct dhcp_packet);
        pointer +=  sizeof(struct dhcp_packet);

        //get the exact message type of the dhcp request
        uint8_t dhcp_msg_type = 0;
        uint32_t requested_ip = dhcp->ciaddr;
		
		uint32_t responded_ip = dhcp->yiaddr;
		
        //parse dhcp option
        while(data_len > 2) {
            uint8_t dhcp_option = data[pointer];
            uint8_t dhcp_option_len = data[pointer+1];

            if(dhcp_option == 0xff) {
                break;
            } else if(dhcp_option == 53) {
                dhcp_msg_type = data[pointer + 2];
				
                if((dhcp_msg_type <1) || (dhcp_msg_type > 8)) {
                    log.err("Invalid DHCP Message Type : %d", dhcp_msg_type);
                    return;
                } 
                if (dhcp_msg_type == DHCPACK){
					  struct in_addr in;
					  in.s_addr = responded_ip;
					  ethernetaddr clientaddr = ethernetaddr(dhcp->chaddr);
					  //this->addDHCPRecord("add", inet_ntoa(in), clientaddr.string().c_str(), "");
				}    
            }else if(dhcp_option == 50) {
                memcpy(&requested_ip, data + pointer + 2, 4);
                struct in_addr in;
                in.s_addr = requested_ip;
              
            } else if(dhcp_option == 12) {

                buf = boost::shared_array<char>(new char[dhcp_option_len + 1]);
                hostname = buf.get();
                memset(hostname, '\0', dhcp_option_len + 1);
                memcpy(hostname, (data + pointer + 2), dhcp_option_len);
            }

            data_len -=(2 + dhcp_option_len );
            pointer +=(2 + dhcp_option_len );
        }
		
        if(dhcp_msg_type == DHCPINFORM) {
            //TODO: we shoulf be replying with a DHCPACK on this one. 
            return;
        } else if(dhcp_msg_type == DHCPDECLINE){
            // the server receives a DHCPDECLINE message, the client has discovered 
            // through some other means that the suggested network address is already in use.
            return;
        }
}

void MonitorSwitch::fromDNSNameFormat(string& question){
	
	char p;
	
	int i, j;
	
	string dns(question);
	
	question.clear();
	
	for (i = 0; i < static_cast<int>(dns.length()); i++){
		p = dns[i];
		for (j = 0; j < (int) p; j++)
			question.push_back(dns[++i]);
		if (i < static_cast<int>(dns.length())-1)
			question.push_back('.');
	}
}

void MonitorSwitch::addDNSRecord(const char* ts, const char *mac, const char *ip, const char *url) {
    
    char q[SOCK_RECV_BUF_LEN];
    unsigned int bytes = 0;
     memset(q, 0, SOCK_RECV_BUF_LEN);
	bytes += sprintf(q + bytes, "SQL:insert into DNSRequest values (" );
	/* time */
	bytes += sprintf(q + bytes, "\"%s\", ", ts);
	/* mac address */
	bytes += sprintf(q + bytes, "\"%s\", ", mac);
	/* ip address */
	bytes += sprintf(q + bytes, "\"%s\", ", ip);
	/* url */
	bytes += sprintf(q + bytes, "\"%s\")\n", url);
	
	int res;
	res = hwdb->insert(q);
	
	if (res != 0) {
		log.err("Insert failed.\n");
	}

}

void MonitorSwitch::addDHCPRecord(const char *action, const char *ip, 
            const char *mac, const char *hostname) {
    char q[SOCK_RECV_BUF_LEN];
    unsigned int bytes = 0;
     memset(q, 0, SOCK_RECV_BUF_LEN);
	bytes += sprintf(q + bytes, "SQL:insert into Leases values (" );
	/* mac address */
	bytes += sprintf(q + bytes, "\"%s\", ", mac);
	/* ip address */
	bytes += sprintf(q + bytes, "\"%s\", ", ip);
	/* hostname (optional) */
	bytes += sprintf(q + bytes, "\"%s\", ", hostname);
	/* action */
	bytes += sprintf(q + bytes, "\"%s\") on duplicate key update\n", action);

	int res;
	res = hwdb->insert(q);
	
	if (res != 0) {
		log.err("Insert failed.\n");
	}
}

Disposition
MonitorSwitch::handle(const Event& e)
{
	
	const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
	uint32_t buffer_id = pi.buffer_id;
    Flow flow(pi.in_port, *pi.get_buffer());
    
    if( (flow.dl_type == ethernet::IP) || (flow.nw_proto == ip_::proto::UDP)){
    
    	if ( (ntohs(flow.tp_dst) == 68) && (ntohs(flow.tp_src) == 67)) {
	 		this->recordDHCP(flow,pi);
		}
		
		if (ntohs(flow.tp_dst) == 53) {
			this->recordDNS(flow, pi);
		}
	}
	
    return CONTINUE;
}



Disposition MonitorSwitch::datapath_join_handler(const Event& e) {
	const Datapath_join_event& pi = assert_cast<const Datapath_join_event&>(e);
	this->registered_datapath.push_back( new datapathid(pi.datapath_id));

	std::vector<boost::shared_array<char> > act;
	Flow flow;
	struct ofp_action_output *ofp_act_out;
	uint32_t wildcard = ~(OFPFW_DL_TYPE | OFPFW_NW_PROTO | OFPFW_TP_SRC | OFPFW_TP_DST);
	boost::shared_array<char> ofp_out(new char[sizeof(struct ofp_action_output)]);
	act.push_back(ofp_out);
	ofp_act_out=(struct ofp_action_output *)ofp_out.get();

	ofp_act_out->type = htons(OFPAT_OUTPUT);
	ofp_act_out->len = htons(sizeof(struct ofp_action_output));
	ofp_act_out->port = htons(OFPP_CONTROLLER); 
	ofp_act_out->max_len = htons(2000);

	//force to forward dhcp traffic to the controller
	//this is required, because otherwise, we won't get full payloaded packet
	wildcard = ~(OFPFW_DL_TYPE | OFPFW_NW_PROTO | OFPFW_TP_SRC | OFPFW_TP_DST); 
	flow.dl_type = ethernet::IP;
	flow.nw_proto = ip_::proto::UDP;
	flow.tp_src = htons(67);
	flow.tp_dst = htons(68);  
	this->send_flow_modification (flow, wildcard, pi.datapath_id,
			-1, OFPFC_ADD, OFP_FLOW_PERMANENT, OFP_DEFAULT_PRIORITY+1, act);
	
	//force forwarding of DNS traffic??
	
	Flow dnsflow;
	dnsflow.dl_type = ethernet::IP;
	dnsflow.nw_proto = ip_::proto::UDP;
	dnsflow.tp_dst = htons(53);  
	
	this->send_flow_modification (dnsflow, wildcard, pi.datapath_id,
			-1, OFPFC_ADD, OFP_FLOW_PERMANENT, OFP_DEFAULT_PRIORITY+1, act);
	
	
	

	return CONTINUE;
}

Disposition MonitorSwitch::datapath_leave_handler(const Event& e) {
	const Datapath_leave_event& pi = assert_cast<const Datapath_leave_event&>(e);
	vector<datapathid *>::iterator it;
	for(it = this->registered_datapath.begin() ; it < this->registered_datapath.end() ; it++) {
		if(pi.datapath_id == (const datapathid& )(**it)) {
			delete *it;
			this->registered_datapath.erase(it);
			break;
		}
	}
	return CONTINUE;
}


bool MonitorSwitch::send_flow_modification (Flow flow, uint32_t wildcard,  datapathid datapath_id,
			uint32_t buffer_id, uint16_t command, uint16_t timeout, uint16_t prio,
			std::vector<boost::shared_array<char> > act) {

	std::vector< boost::shared_array<char> >::iterator iter;
	ofp_flow_mod* ofm;
	size_t size = sizeof(*ofm);
	struct ofp_action_header *ofp_hdr;

	for(iter = act.begin() ; iter != act.end(); iter++) {
		ofp_hdr = (struct ofp_action_header *)iter->get();
		size += ntohs(ofp_hdr->len);
	}
	boost::shared_array<char> raw_of(new char[size]);
	ofm = (ofp_flow_mod*) raw_of.get();
	ofm->header.version = OFP_VERSION;
	ofm->header.type = OFPT_FLOW_MOD;
	ofm->header.length = htons(size);
	ofm->match.wildcards = htonl(wildcard);
	ofm->match.in_port = htons(flow.in_port);
	ofm->match.dl_vlan = flow.dl_vlan;
	ofm->match.dl_vlan_pcp = flow.dl_vlan_pcp;
	memcpy(ofm->match.dl_src, flow.dl_src.octet, sizeof ofm->match.dl_src);
	memcpy(ofm->match.dl_dst, flow.dl_dst.octet, sizeof ofm->match.dl_dst);
	ofm->match.dl_type = flow.dl_type;
	ofm->match.nw_src = flow.nw_src;
	ofm->match.nw_dst = flow.nw_dst;
	ofm->match.nw_proto = flow.nw_proto;
	ofm->match.nw_tos = flow.nw_tos;
	ofm->match.tp_src = flow.tp_src;
	ofm->match.tp_dst = flow.tp_dst;
	ofm->cookie = htonl(0);
	ofm->command = htons(command);
	ofm->buffer_id = htonl(buffer_id);
	ofm->idle_timeout = htons(timeout);
	ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
	ofm->priority = htons(prio); //htons(OFP_DEFAULT_PRIORITY);
	ofm->flags = htons( OFPFF_SEND_FLOW_REM); // | OFPFF_CHECK_OVERLAP);

	char *data = (char *)ofm->actions;
	int pos = 0;
	for(iter = act.begin() ; iter != act.end(); iter++) {
		ofp_hdr = (struct ofp_action_header *)iter->get();
		memcpy(data+pos, iter->get(), ntohs(ofp_hdr->len));
		pos += ntohs(ofp_hdr->len);
	}
	send_openflow_command(datapath_id, &ofm->header, false);
	return true;
}


bool MonitorSwitch::extract_headers(uint8_t *data, uint32_t data_len, struct nw_hdr *hdr) {
	uint32_t pointer = 0;

	if(data_len < sizeof( struct ether_header))
		return false;

	// parse ethernet header
	hdr->ether = (struct ether_header *) data;
	pointer += sizeof( struct ether_header);
	data_len -=  sizeof( struct ether_header);

	// parse ip header
	if(data_len < sizeof(struct iphdr))
		return false;
	hdr->ip = (struct iphdr *) (data + pointer);
	if(data_len < hdr->ip->ihl*4) 
		return false;
	pointer += hdr->ip->ihl*4;
	data_len -= hdr->ip->ihl*4;

	//parse udp header
	if(hdr->ip->protocol == ip_::proto::UDP) {
		hdr->udp = (struct udphdr *)(data + pointer);
		hdr->data = data + pointer + sizeof(struct udphdr);    
	} else if(hdr->ip->protocol == ip_::proto::TCP) {
		hdr->tcp = (struct tcphdr *)(data + pointer);
		hdr->data = data + pointer + (hdr->tcp->doff*4);
	} else if(hdr->ip->protocol == ip_::proto::IGMP) {
		hdr->igmp = (struct igmphdr *)(data + pointer);
	} else {
		return false;
	}
	return true;
}

REGISTER_COMPONENT(container::Simple_component_factory<MonitorSwitch>, MonitorSwitch);

} // vigil namespace
