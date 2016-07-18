"""
Fuzzer for openflow
"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import time

from oftest.testutils import *


class stats_request(message):
    subtypes = {}

    version = 4
    type = 18

    def __init__(self, xid=None, stats_type=None, flags=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if stats_type is not None:
            self.stats_type = stats_type
        else:
            self.stats_type = 0
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        subtype, = reader.peek('!H', 8)
        subclass = stats_request.subtypes.get(subtype)
        if subclass:
            return subclass.unpack(reader)

        obj = stats_request()
        _version = reader.read("!B")[0]
        assert(_version == 4)
        _type = reader.read("!B")[0]
        assert(_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.stats_type = reader.read("!H")[0]
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.stats_type != other.stats_type:
            return False
        if self.flags != other.flags:
            return False
        return True

    def pretty_print(self, q):
        q.text("stats_request {")
        with q.group():
            with q.indent(2):
                q.breakable()
                q.text("xid = ")
                if self.xid is not None:
                    q.text("%#x" % self.xid)
                else:
                    q.text('None')
                q.text(",")
                q.breakable()
                q.text("flags = ")
                q.text("%#x" % self.flags)
            q.breakable()
        q.text('}')

message.subtypes[18] = stats_request
