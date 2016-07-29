import sys
import copy
import logging
import types
import time
import re
import packet as scapy

import oftest
import oftest.controller
import oftest.dataplane
import oftest.parse
import oftest.ofutils
import ofp
import ofp
import time
import random

global skipped_test_count
skipped_test_count = 0

_import_blacklist = set(locals().keys())

# Some useful defines
IP_ETHERTYPE = 0x800
TCP_PROTOCOL = 0x6
UDP_PROTOCOL = 0x11

MINSIZE = 0



def add(self,commande,iteration=1, xid=None, length=None, version = 4, type = None, bversion="!B", btype="!B", blength="!H", bxid = "!L", data = None):
	if iteration != 1:
		self.iteration = iteration
	else:
		self.iteration = iteration
	print(00)

	if commande=="flow_add":
		out_port, = openflow_ports(1)
		parsed_pkt = simple_tcp_packet()
		pkt = str(parsed_pkt)
		match = patcket_to_flow_match(self,parsed_pkt)
		if type is not None:
			self.type = type
		else:
			self.type = 14
		for i in range(iteration):
			request=ofp.message.flow_add(
                   xid,
                   length,
                   version,
                   self.type,
                   table_id=test_param_get("table", 0),
                   cookie=24,
                   match=match,
                   instructions=[
                       ofp.instruction.apply_actions(
                           actions=[
                               ofp.action.output(
                                   port=out_port,
                                   max_len=ofp.OFPCML_NO_BUFFER)])],
                   buffer_id=ofp.OFP_NO_BUFFER,
                   priority=1000)
			self.controller.message_send(request)

	if commande=="echo":
		if type is not None:
			self.type = type
		else:
			self.type = 2
		for i in range(self.iteration):
			request = ofp.fuzzer.echo_request(xid, length, version, self.type, bversion, btype, blength, bxid, data)
			self.controller.message_send(request)


	if commande=="flow_del":
		for i in range(self.iteration):
			delete_all_flows(self.controller)

	if commande=="barrier":
		if type is not None:
			self.type = type
		else:
			self.type = 20
		for i in range(self.iteration):
			request = ofp.fuzzer.barrier_request(xid, length, version, self.type, bversion, btype, blength, bxid)
			self.controller.message_send(request)

	request = ofp.fuzzer.echo_request()
	response, pkt = self.controller.transact(request)
	self.assertTrue(response is not None,
                    "Did not get echo reply")
	self.assertEqual(response.type, ofp.OFPT_ECHO_REPLY,
                    'response is not echo_reply')
	self.assertEqual(request.xid, response.xid,
                    'response xid != request xid')
	self.assertEqual(len(response.data), 0, 'response data non-empty')

	out_port, = openflow_ports(1)
	parsed_pkt = simple_tcp_packet()
	pkt = str(parsed_pkt)
	match = packet_to_flow_match(self,parsed_pkt)

	request = ofp.message.flow_add(
            table_id=test_param_get("table", 0),
            cookie=42,
            match=match,
            instructions=[
                ofp.instruction.apply_actions(
                    actions=[
                        ofp.action.output(
                            port=out_port,
                            max_len=ofp.OFPCML_NO_BUFFER)])],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=1000)

	self.controller.message_send(request)
	do_barrier(self.controller)

	delete_all_flows(self.controller)
	delete_all_flows(self.controller)
	
	return 0

def test_param_get(key, default=None):
    """
    Return value passed via test-params if present

    @param key The lookup key
    @param default Default value to use if not found

    If the pair 'key=val' appeared in the string passed to --test-params
    on the command line, return val (as interpreted by exec).  Otherwise
    return default value.

    WARNING: TEST PARAMETERS MUST BE PYTHON IDENTIFIERS; 
    eg egr_count, not egr-count.
    """
    try:
        exec oftest.config["test_params"]
    except:
        return default

    try:
        return eval(str(key))
    except:
        return default
        
def openflow_ports(num=None):
    """
    Return a list of 'num' OpenFlow port numbers

    If 'num' is None, return all available ports. Otherwise, limit the length
    of the result to 'num' and raise an exception if not enough ports are
    available.
    """
    ports = sorted(oftest.config["port_map"].keys())
    if num != None and len(ports) < num:
        raise Exception("test requires %d ports but only %d are available" % (num, len(ports)))
    return ports[:num]

def simple_tcp_packet(pktlen=100, 
                      eth_dst='00:01:02:03:04:05',
                      eth_src='00:06:07:08:09:0a',
                      dl_vlan_enable=False,
                      vlan_vid=0,
                      vlan_pcp=0,
                      dl_vlan_cfi=0,
                      ip_src='192.168.0.1',
                      ip_dst='192.168.0.2',
                      ip_tos=0,
                      ip_ttl=64,
                      tcp_sport=1234,
                      tcp_dport=80,
                      tcp_flags="S",
                      ip_ihl=None,
                      ip_options=False
                      ):
    """
    Return a simple dataplane TCP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destinatino MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ttl IP TTL
    @param tcp_dport TCP destination port
    @param tcp_sport TCP source port
    @param tcp_flags TCP Control flags  	

    Generates a simple TCP request.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/IP/TCP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, ihl=ip_ihl)/ \
            scapy.TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags)
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, ihl=ip_ihl)/ \
                scapy.TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags)
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, ihl=ip_ihl, options=ip_options)/ \
                scapy.TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags)

    pkt = pkt/("D" * (pktlen - len(pkt)))

    return pkt
def do_barrier(ctrl, timeout=-1):
    """
    Do a barrier command
    Return 0 on success, -1 on error
    """
    b = ofp.message.barrier_request()
    (resp, pkt) = ctrl.transact(b, timeout=timeout)
    if resp is None:
        raise AssertionError("barrier failed")
    # We'll trust the transaction processing in the controller that xid matched
    return 0 # for backwards compatibility

def delete_all_flows(ctrl, send_barrier=True):
    """
    Delete all flows on the switch
    @param ctrl The controller object for the test
    @param send_barrier Whether or not to send a barrier message
    """

    logging.info("Deleting all flows")
    msg = ofp.message.flow_delete()
    if ofp.OFP_VERSION in [1, 2]:
        msg.match.wildcards = ofp.OFPFW_ALL
        msg.out_port = ofp.OFPP_NONE
        msg.buffer_id = 0xffffffff
    elif ofp.OFP_VERSION >= 3:
        msg.table_id = ofp.OFPTT_ALL
        msg.buffer_id = ofp.OFP_NO_BUFFER
        msg.out_port = ofp.OFPP_ANY
        msg.out_group = ofp.OFPG_ANY
    ctrl.message_send(msg)
    if send_barrier:
        do_barrier(ctrl)
    return 0 # for backwards compatibility
def packet_to_flow_match(parent, packet):
    match = oftest.parse.packet_to_flow_match(packet)
    if ofp.OFP_VERSION in [1, 2]:
        match.wildcards |= required_wildcards(parent)
    else:
        # TODO remove incompatible OXM entries
        pass
    return match
