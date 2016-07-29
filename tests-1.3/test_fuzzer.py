import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import time
import random

from oftest.testutils import *
from oftest.parser import *


@group('smoke')
class Echo(base_tests.SimpleProtocol):
    """
    Test echo response with no data
    """

    def runTest(self):
        add(self,"echo", 1)
