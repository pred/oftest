import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import time
import random

from oftest.testutils import *

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


