"""
Fuzzer for openflow
"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import time

from oftest.testutils import *

