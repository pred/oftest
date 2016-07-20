# Distributed under the OpenFlow Software License (see LICENSE)
# Copyright (c) 2010 The Board of Trustees of The Leland Stanford Junior University
# Copyright (c) 2012, 2013 Big Switch Networks, Inc.
# Copyright (c) 2012, 2013 CPqD
# Copyright (c) 2012, 2013 Ericsson
"""
Basic test cases

Test cases in other modules depend on this functionality.
"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import time

from oftest.testutils import *


@group('smoke')
class Echo(base_tests.SimpleProtocol):
    """
    Test echo response with no data
    """

    def runTest(self):
        request = ofp.message.echo_request()
        response, pkt = self.controller.transact(request)
        while true:
            request = ofp.fuzzer.echo_request()
            response, pkt = self.controller.transact(request)
        self.assertTrue(response is not None,
                        "Did not get echo reply")
        self.assertEqual(response.type, ofp.OFPT_ECHO_REPLY,
                        'response is not echo_reply')
        self.assertEqual(request.xid, response.xid,
                        'response xid != request xid')
        self.assertEqual(len(response.data), 0, 'response data non-empty')
