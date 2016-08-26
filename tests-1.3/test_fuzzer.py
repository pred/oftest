import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import time
import random

from oftest.testutils import *
from oftest.parser import *


@group('smoke')
class Fuzz(base_tests.SimpleProtocol):
    """
    add(self,nameOfMessage,iteration,xid,length,version,type,bversion,btype,blength,bxid,data)

    nameOfMessage : Only mandatory argument, it can either be "flow\_add", "echo" "flow\_del" (which delete all flows regardless of the argument) or "barrier".
    iteration : number of times the message should be sent (default = 1)
    xid : if you want to modify the xid of the message (int)
    length : if you want to modify the length (int)
    version : if you want to modify the version of Openflow, (int, default = 4 for 1.3)
    type : this field is used to tell the switch what the message is, default : 14 for flow\_add, 2 for echo, and 20 for barrier.
    bversion, btype, blength, bxid specified on how many bytes the field is set. It can be "!B", "!H" or "!L"
    data : this field is relevant for echo messages which can contains data, default = None.

    example
    add(self,"echo",xid=42,data = "this is a test")
    add(self,"flow\_add", iteration = 100000, bversion="!H")

    """
    def runTest(self):
        add(self,)

