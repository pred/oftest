import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import time
import random

from oftest.testutils import *


@group('smoke')
class Echo(base_tests.SimpleProtocol):
    """
    Test echo response with no data
    """

    def runTest(self):
        while True:
            request = ofp.fuzzer.echo_request()
            response, pkt = self.controller.transact(request)
        self.assertTrue(response is not None,
                        "Did not get echo reply")
        self.assertEqual(response.type, ofp.OFPT_ECHO_REPLY,
                        'response is not echo_reply')
        self.assertEqual(request.xid, response.xid,
                        'response xid != request xid')
        self.assertEqual(len(response.data), 0, 'response data non-empty')


class flow_add(base_tests.SimpleProtocol):
    def runTest(self):
        out_port, = openflow_ports(1)

        request = ofp.message.flow_add(
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
        do_barrier(self.controller)

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