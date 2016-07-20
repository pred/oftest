import struct
import loxi
import util
import loxi.generic_util
from oftest import config

import sys

ofp = sys.modules['loxi.of13']


class fuzzer(loxi.OFObject):
    subtypes = {}

    version = 4

    def __init__(self, type=None, xid=None):
        if type is not None:
            self.type = type
        else:
            self.type = 0
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        subtype, = reader.peek('B', 1)
        subclass = fuzzer.subtypes.get(subtype)
        if subclass:
            return subclass.unpack(reader)

        obj = fuzzer()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        obj.type = reader.read("!B")[0]
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.type != other.type:
            return False
        if self.xid != other.xid:
            return False
        return True

    def pretty_print(self, q):
        q.text("fuzzer {")
        with q.group():
            with q.indent(2):
                q.breakable()
                q.text("xid = ")
                if self.xid is not None:
                    q.text("%#x" % self.xid)
                else:
                    q.text('None')
            q.breakable()
        q.text('}')


class multipart_request(fuzzer):
    subtypes = {}

    def __init__(self, xid=None, stats_type=None, flags=None, version=None, type=None):
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
        if version is not None:
            self.version = version
        else:
            self.version = 4
        if type is not None:
            self.type = type
        else:
            self.type = 18
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
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
        subclass = multipart_request.subtypes.get(subtype)
        if subclass:
            return subclass.unpack(reader)

        obj = multipart_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
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
        q.text("multipart_request {")
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


fuzzer.subtypes[18] = multipart_request


class stats_request(fuzzer):
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
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
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
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
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


fuzzer.subtypes[18] = stats_request


class aggregate_stats_request(stats_request):
    version = 4
    type = 18
    stats_type = 2

    def __init__(self, xid=None, flags=None, table_id=None, out_port=None, out_group=None, cookie=None,
                 cookie_mask=None, match=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if table_id is not None:
            self.table_id = table_id
        else:
            self.table_id = 0
        if out_port is not None:
            self.out_port = out_port
        else:
            self.out_port = 0
        if out_group is not None:
            self.out_group = out_group
        else:
            self.out_group = 0
        if cookie is not None:
            self.cookie = cookie
        else:
            self.cookie = 0
        if cookie_mask is not None:
            self.cookie_mask = cookie_mask
        else:
            self.cookie_mask = 0
        if match is not None:
            self.match = match
        else:
            self.match = ofp.match()
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        packed.append(struct.pack("!B", self.table_id))
        packed.append('\x00' * 3)
        packed.append(util.pack_port_no(self.out_port))
        packed.append(struct.pack("!L", self.out_group))
        packed.append('\x00' * 4)
        packed.append(struct.pack("!Q", self.cookie))
        packed.append(struct.pack("!Q", self.cookie_mask))
        packed.append(self.match.pack())
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = aggregate_stats_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _stats_type = reader.read("!H")[0]
        assert (_stats_type == 2)
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        obj.table_id = reader.read("!B")[0]
        reader.skip(3)
        obj.out_port = util.unpack_port_no(reader)
        obj.out_group = reader.read("!L")[0]
        reader.skip(4)
        obj.cookie = reader.read("!Q")[0]
        obj.cookie_mask = reader.read("!Q")[0]
        obj.match = ofp.match.unpack(reader)
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.flags != other.flags:
            return False
        if self.table_id != other.table_id:
            return False
        if self.out_port != other.out_port:
            return False
        if self.out_group != other.out_group:
            return False
        if self.cookie != other.cookie:
            return False
        if self.cookie_mask != other.cookie_mask:
            return False
        if self.match != other.match:
            return False
        return True

    def pretty_print(self, q):
        q.text("aggregate_stats_request {")
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
                q.text(",")
                q.breakable()
                q.text("table_id = ")
                q.text("%#x" % self.table_id)
                q.text(",")
                q.breakable()
                q.text("out_port = ")
                q.text(util.pretty_port(self.out_port))
                q.text(",")
                q.breakable()
                q.text("out_group = ")
                q.text("%#x" % self.out_group)
                q.text(",")
                q.breakable()
                q.text("cookie = ")
                q.text("%#x" % self.cookie)
                q.text(",")
                q.breakable()
                q.text("cookie_mask = ")
                q.text("%#x" % self.cookie_mask)
                q.text(",")
                q.breakable()
                q.text("match = ")
                q.pp(self.match)
            q.breakable()
        q.text('}')


stats_request.subtypes[2] = aggregate_stats_request


class async_get_request(fuzzer):
    version = 4
    type = 26

    def __init__(self, xid=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = async_get_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 26)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        return True

    def pretty_print(self, q):
        q.text("async_get_request {")
        with q.group():
            with q.indent(2):
                q.breakable()
                q.text("xid = ")
                if self.xid is not None:
                    q.text("%#x" % self.xid)
                else:
                    q.text('None')
            q.breakable()
        q.text('}')


fuzzer.subtypes[26] = async_get_request


class async_set(fuzzer):
    version = 4
    type = 28

    def __init__(self, xid=None, packet_in_mask_equal_master=None, packet_in_mask_slave=None,
                 port_status_mask_equal_master=None, port_status_mask_slave=None, flow_removed_mask_equal_master=None,
                 flow_removed_mask_slave=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if packet_in_mask_equal_master is not None:
            self.packet_in_mask_equal_master = packet_in_mask_equal_master
        else:
            self.packet_in_mask_equal_master = 0
        if packet_in_mask_slave is not None:
            self.packet_in_mask_slave = packet_in_mask_slave
        else:
            self.packet_in_mask_slave = 0
        if port_status_mask_equal_master is not None:
            self.port_status_mask_equal_master = port_status_mask_equal_master
        else:
            self.port_status_mask_equal_master = 0
        if port_status_mask_slave is not None:
            self.port_status_mask_slave = port_status_mask_slave
        else:
            self.port_status_mask_slave = 0
        if flow_removed_mask_equal_master is not None:
            self.flow_removed_mask_equal_master = flow_removed_mask_equal_master
        else:
            self.flow_removed_mask_equal_master = 0
        if flow_removed_mask_slave is not None:
            self.flow_removed_mask_slave = flow_removed_mask_slave
        else:
            self.flow_removed_mask_slave = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!L", self.packet_in_mask_equal_master))
        packed.append(struct.pack("!L", self.packet_in_mask_slave))
        packed.append(struct.pack("!L", self.port_status_mask_equal_master))
        packed.append(struct.pack("!L", self.port_status_mask_slave))
        packed.append(struct.pack("!L", self.flow_removed_mask_equal_master))
        packed.append(struct.pack("!L", self.flow_removed_mask_slave))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = async_set()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 28)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.packet_in_mask_equal_master = reader.read("!L")[0]
        obj.packet_in_mask_slave = reader.read("!L")[0]
        obj.port_status_mask_equal_master = reader.read("!L")[0]
        obj.port_status_mask_slave = reader.read("!L")[0]
        obj.flow_removed_mask_equal_master = reader.read("!L")[0]
        obj.flow_removed_mask_slave = reader.read("!L")[0]
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.packet_in_mask_equal_master != other.packet_in_mask_equal_master:
            return False
        if self.packet_in_mask_slave != other.packet_in_mask_slave:
            return False
        if self.port_status_mask_equal_master != other.port_status_mask_equal_master:
            return False
        if self.port_status_mask_slave != other.port_status_mask_slave:
            return False
        if self.flow_removed_mask_equal_master != other.flow_removed_mask_equal_master:
            return False
        if self.flow_removed_mask_slave != other.flow_removed_mask_slave:
            return False
        return True

    def pretty_print(self, q):
        q.text("async_set {")
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
                q.text("packet_in_mask_equal_master = ")
                q.text("%#x" % self.packet_in_mask_equal_master)
                q.text(",")
                q.breakable()
                q.text("packet_in_mask_slave = ")
                q.text("%#x" % self.packet_in_mask_slave)
                q.text(",")
                q.breakable()
                q.text("port_status_mask_equal_master = ")
                q.text("%#x" % self.port_status_mask_equal_master)
                q.text(",")
                q.breakable()
                q.text("port_status_mask_slave = ")
                q.text("%#x" % self.port_status_mask_slave)
                q.text(",")
                q.breakable()
                q.text("flow_removed_mask_equal_master = ")
                q.text("%#x" % self.flow_removed_mask_equal_master)
                q.text(",")
                q.breakable()
                q.text("flow_removed_mask_slave = ")
                q.text("%#x" % self.flow_removed_mask_slave)
            q.breakable()
        q.text('}')


fuzzer.subtypes[28] = async_set


class error_msg(fuzzer):
    subtypes = {}

    version = 4
    type = 1

    def __init__(self, xid=None, err_type=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if err_type is not None:
            self.err_type = err_type
        else:
            self.err_type = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        subtype, = reader.peek('!H', 8)
        subclass = error_msg.subtypes.get(subtype)
        if subclass:
            return subclass.unpack(reader)

        obj = error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.err_type = reader.read("!H")[0]
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.err_type != other.err_type:
            return False
        return True

    def pretty_print(self, q):
        q.text("error_msg {")
        with q.group():
            with q.indent(2):
                q.breakable()
                q.text("xid = ")
                if self.xid is not None:
                    q.text("%#x" % self.xid)
                else:
                    q.text('None')
            q.breakable()
        q.text('}')


fuzzer.subtypes[1] = error_msg


class bad_action_error_msg(error_msg):
    version = 4
    type = 1
    err_type = 2

    def __init__(self, xid=None, code=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if code is not None:
            self.code = code
        else:
            self.code = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        packed.append(struct.pack("!H", self.code))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = bad_action_error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _err_type = reader.read("!H")[0]
        assert (_err_type == 2)
        obj.code = reader.read("!H")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.code != other.code:
            return False
        if self.data != other.data:
            return False
        return True

    def pretty_print(self, q):
        q.text("bad_action_error_msg {")
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
                q.text("code = ")
                q.text("%#x" % self.code)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


error_msg.subtypes[2] = bad_action_error_msg


class bad_instruction_error_msg(error_msg):
    version = 4
    type = 1
    err_type = 3

    def __init__(self, xid=None, code=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if code is not None:
            self.code = code
        else:
            self.code = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        packed.append(struct.pack("!H", self.code))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = bad_instruction_error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _err_type = reader.read("!H")[0]
        assert (_err_type == 3)
        obj.code = reader.read("!H")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.code != other.code:
            return False
        if self.data != other.data:
            return False
        return True

    def pretty_print(self, q):
        q.text("bad_instruction_error_msg {")
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
                q.text("code = ")
                q.text("%#x" % self.code)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


error_msg.subtypes[3] = bad_instruction_error_msg


class bad_match_error_msg(error_msg):
    version = 4
    type = 1
    err_type = 4

    def __init__(self, xid=None, code=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if code is not None:
            self.code = code
        else:
            self.code = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        packed.append(struct.pack("!H", self.code))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = bad_match_error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _err_type = reader.read("!H")[0]
        assert (_err_type == 4)
        obj.code = reader.read("!H")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.code != other.code:
            return False
        if self.data != other.data:
            return False
        return True

    def pretty_print(self, q):
        q.text("bad_match_error_msg {")
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
                q.text("code = ")
                q.text("%#x" % self.code)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


error_msg.subtypes[4] = bad_match_error_msg


class bad_request_error_msg(error_msg):
    version = 4
    type = 1
    err_type = 1

    def __init__(self, xid=None, code=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if code is not None:
            self.code = code
        else:
            self.code = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        packed.append(struct.pack("!H", self.code))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = bad_request_error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _err_type = reader.read("!H")[0]
        assert (_err_type == 1)
        obj.code = reader.read("!H")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.code != other.code:
            return False
        if self.data != other.data:
            return False
        return True

    def pretty_print(self, q):
        q.text("bad_request_error_msg {")
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
                q.text("code = ")
                q.text("%#x" % self.code)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


error_msg.subtypes[1] = bad_request_error_msg


class barrier_request(fuzzer):
    version = 4
    type = 20

    def __init__(self, xid=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = barrier_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 20)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        return True

    def pretty_print(self, q):
        q.text("barrier_request {")
        with q.group():
            with q.indent(2):
                q.breakable()
                q.text("xid = ")
                if self.xid is not None:
                    q.text("%#x" % self.xid)
                else:
                    q.text('None')
            q.breakable()
        q.text('}')


fuzzer.subtypes[20] = barrier_request


class experimenter(fuzzer):
    subtypes = {}

    version = 4
    type = 4

    def __init__(self, xid=None, experimenter=None, subtype=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if experimenter is not None:
            self.experimenter = experimenter
        else:
            self.experimenter = 0
        if subtype is not None:
            self.subtype = subtype
        else:
            self.subtype = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!L", self.experimenter))
        packed.append(struct.pack("!L", self.subtype))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        subtype, = reader.peek('!L', 8)
        subclass = experimenter.subtypes.get(subtype)
        if subclass:
            return subclass.unpack(reader)

        obj = experimenter()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 4)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.experimenter = reader.read("!L")[0]
        obj.subtype = reader.read("!L")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.experimenter != other.experimenter:
            return False
        if self.subtype != other.subtype:
            return False
        if self.data != other.data:
            return False
        return True

    def pretty_print(self, q):
        q.text("experimenter {")
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
                q.text("subtype = ")
                q.text("%#x" % self.subtype)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


fuzzer.subtypes[4] = experimenter


class experimenter_error_msg(error_msg):
    subtypes = {}

    version = 4
    type = 1
    err_type = 65535

    def __init__(self, xid=None, subtype=None, experimenter=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if subtype is not None:
            self.subtype = subtype
        else:
            self.subtype = 0
        if experimenter is not None:
            self.experimenter = experimenter
        else:
            self.experimenter = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        packed.append(struct.pack("!H", self.subtype))
        packed.append(struct.pack("!L", self.experimenter))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        subtype, = reader.peek('!L', 12)
        subclass = experimenter_error_msg.subtypes.get(subtype)
        if subclass:
            return subclass.unpack(reader)

        obj = experimenter_error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _err_type = reader.read("!H")[0]
        assert (_err_type == 65535)
        obj.subtype = reader.read("!H")[0]
        obj.experimenter = reader.read("!L")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.subtype != other.subtype:
            return False
        if self.experimenter != other.experimenter:
            return False
        if self.data != other.data:
            return False
        return True

    def pretty_print(self, q):
        q.text("experimenter_error_msg {")
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
                q.text("subtype = ")
                q.text("%#x" % self.subtype)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


error_msg.subtypes[65535] = experimenter_error_msg


class experimenter_stats_request(stats_request):
    subtypes = {}

    version = 4
    type = 18
    stats_type = 65535

    def __init__(self, xid=None, flags=None, experimenter=None, subtype=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if experimenter is not None:
            self.experimenter = experimenter
        else:
            self.experimenter = 0
        if subtype is not None:
            self.subtype = subtype
        else:
            self.subtype = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        packed.append(struct.pack("!L", self.experimenter))
        packed.append(struct.pack("!L", self.subtype))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        subtype, = reader.peek('!L', 16)
        subclass = experimenter_stats_request.subtypes.get(subtype)
        if subclass:
            return subclass.unpack(reader)

        obj = experimenter_stats_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _stats_type = reader.read("!H")[0]
        assert (_stats_type == 65535)
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        obj.experimenter = reader.read("!L")[0]
        obj.subtype = reader.read("!L")[0]
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.flags != other.flags:
            return False
        if self.experimenter != other.experimenter:
            return False
        if self.subtype != other.subtype:
            return False
        return True

    def pretty_print(self, q):
        q.text("experimenter_stats_request {")
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
                q.text(",")
                q.breakable()
                q.text("subtype = ")
                q.text("%#x" % self.subtype)
            q.breakable()
        q.text('}')


stats_request.subtypes[65535] = experimenter_stats_request


class desc_stats_request(stats_request):
    version = 4
    type = 18
    stats_type = 0

    def __init__(self, xid=None, flags=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = desc_stats_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _stats_type = reader.read("!H")[0]
        assert (_stats_type == 0)
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.flags != other.flags:
            return False
        return True

    def pretty_print(self, q):
        q.text("desc_stats_request {")
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


stats_request.subtypes[0] = desc_stats_request


class echo_request(fuzzer):

    def __init__(self, xid=None, data=None, version=4, type=2, length=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if data is not None:
            self.data = data
        else:
            self.data = ''
        if version != 4:
            self.version = version
        else:
            self.version = 2
        if type != 2:
            self.type = type
        else:
            self.type = 2
        if length is not None:
            self.length = length
        else:
            self.length = None
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(self.data)
        if self.length is not None:
            packed[2] = struct.pack("!H", self.length)
        else:
            length = sum([len(x) for x in packed])
            packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = echo_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 2)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.data != other.data:
            return False
        return True

    def pretty_print(self, q):
        q.text("echo_request {")
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
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


fuzzer.subtypes[2] = echo_request


class features_request(fuzzer):
    version = 4
    type = 5

    def __init__(self, xid=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = features_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 5)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        return True

    def pretty_print(self, q):
        q.text("features_request {")
        with q.group():
            with q.indent(2):
                q.breakable()
                q.text("xid = ")
                if self.xid is not None:
                    q.text("%#x" % self.xid)
                else:
                    q.text('None')
            q.breakable()
        q.text('}')


fuzzer.subtypes[5] = features_request


class flow_mod(fuzzer):
    subtypes = {}

    version = 4
    type = 14

    def __init__(self, xid=None, cookie=None, cookie_mask=None, table_id=None, _command=None, idle_timeout=None,
                 hard_timeout=None, priority=None, buffer_id=None, out_port=None, out_group=None, flags=None,
                 match=None, instructions=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if cookie is not None:
            self.cookie = cookie
        else:
            self.cookie = 0
        if cookie_mask is not None:
            self.cookie_mask = cookie_mask
        else:
            self.cookie_mask = 0
        if table_id is not None:
            self.table_id = table_id
        else:
            self.table_id = 0
        if _command is not None:
            self._command = _command
        else:
            self._command = 0
        if idle_timeout is not None:
            self.idle_timeout = idle_timeout
        else:
            self.idle_timeout = 0
        if hard_timeout is not None:
            self.hard_timeout = hard_timeout
        else:
            self.hard_timeout = 0
        if priority is not None:
            self.priority = priority
        else:
            self.priority = 0
        if buffer_id is not None:
            self.buffer_id = buffer_id
        else:
            self.buffer_id = 0
        if out_port is not None:
            self.out_port = out_port
        else:
            self.out_port = 0
        if out_group is not None:
            self.out_group = out_group
        else:
            self.out_group = 0
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if match is not None:
            self.match = match
        else:
            self.match = ofp.match()
        if instructions is not None:
            self.instructions = instructions
        else:
            self.instructions = []
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!Q", self.cookie))
        packed.append(struct.pack("!Q", self.cookie_mask))
        packed.append(struct.pack("!B", self.table_id))
        packed.append(util.pack_fm_cmd(self._command))
        packed.append(struct.pack("!H", self.idle_timeout))
        packed.append(struct.pack("!H", self.hard_timeout))
        packed.append(struct.pack("!H", self.priority))
        packed.append(struct.pack("!L", self.buffer_id))
        packed.append(util.pack_port_no(self.out_port))
        packed.append(struct.pack("!L", self.out_group))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 2)
        packed.append(self.match.pack())
        packed.append(loxi.generic_util.pack_list(self.instructions))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        subtype, = reader.peek('B', 25)
        subclass = flow_mod.subtypes.get(subtype)
        if subclass:
            return subclass.unpack(reader)

        obj = flow_mod()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 14)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.cookie = reader.read("!Q")[0]
        obj.cookie_mask = reader.read("!Q")[0]
        obj.table_id = reader.read("!B")[0]
        obj._command = util.unpack_fm_cmd(reader)
        obj.idle_timeout = reader.read("!H")[0]
        obj.hard_timeout = reader.read("!H")[0]
        obj.priority = reader.read("!H")[0]
        obj.buffer_id = reader.read("!L")[0]
        obj.out_port = util.unpack_port_no(reader)
        obj.out_group = reader.read("!L")[0]
        obj.flags = reader.read("!H")[0]
        reader.skip(2)
        obj.match = ofp.match.unpack(reader)
        obj.instructions = loxi.generic_util.unpack_list(reader, ofp.instruction.instruction.unpack)
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.cookie != other.cookie:
            return False
        if self.cookie_mask != other.cookie_mask:
            return False
        if self.table_id != other.table_id:
            return False
        if self._command != other._command:
            return False
        if self.idle_timeout != other.idle_timeout:
            return False
        if self.hard_timeout != other.hard_timeout:
            return False
        if self.priority != other.priority:
            return False
        if self.buffer_id != other.buffer_id:
            return False
        if self.out_port != other.out_port:
            return False
        if self.out_group != other.out_group:
            return False
        if self.flags != other.flags:
            return False
        if self.match != other.match:
            return False
        if self.instructions != other.instructions:
            return False
        return True

    def pretty_print(self, q):
        q.text("flow_mod {")
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
                q.text("cookie = ")
                q.text("%#x" % self.cookie)
                q.text(",")
                q.breakable()
                q.text("cookie_mask = ")
                q.text("%#x" % self.cookie_mask)
                q.text(",")
                q.breakable()
                q.text("table_id = ")
                q.text("%#x" % self.table_id)
                q.text(",")
                q.breakable()
                q.text("idle_timeout = ")
                q.text("%#x" % self.idle_timeout)
                q.text(",")
                q.breakable()
                q.text("hard_timeout = ")
                q.text("%#x" % self.hard_timeout)
                q.text(",")
                q.breakable()
                q.text("priority = ")
                q.text("%#x" % self.priority)
                q.text(",")
                q.breakable()
                q.text("buffer_id = ")
                q.text("%#x" % self.buffer_id)
                q.text(",")
                q.breakable()
                q.text("out_port = ")
                q.text(util.pretty_port(self.out_port))
                q.text(",")
                q.breakable()
                q.text("out_group = ")
                q.text("%#x" % self.out_group)
                q.text(",")
                q.breakable()
                q.text("flags = ")
                q.text("%#x" % self.flags)
                q.text(",")
                q.breakable()
                q.text("match = ")
                q.pp(self.match)
                q.text(",")
                q.breakable()
                q.text("instructions = ")
                q.pp(self.instructions)
            q.breakable()
        q.text('}')


fuzzer.subtypes[14] = flow_mod


class flow_add(flow_mod):
    version = 4
    type = 14
    _command = 0

    def __init__(self, xid=None, cookie=None, cookie_mask=None, table_id=None, idle_timeout=None, hard_timeout=None,
                 priority=None, buffer_id=None, out_port=None, out_group=None, flags=None, match=None,
                 instructions=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if cookie is not None:
            self.cookie = cookie
        else:
            self.cookie = 0
        if cookie_mask is not None:
            self.cookie_mask = cookie_mask
        else:
            self.cookie_mask = 0
        if table_id is not None:
            self.table_id = table_id
        else:
            self.table_id = 0
        if idle_timeout is not None:
            self.idle_timeout = idle_timeout
        else:
            self.idle_timeout = 0
        if hard_timeout is not None:
            self.hard_timeout = hard_timeout
        else:
            self.hard_timeout = 0
        if priority is not None:
            self.priority = priority
        else:
            self.priority = 0
        if buffer_id is not None:
            self.buffer_id = buffer_id
        else:
            self.buffer_id = 0
        if out_port is not None:
            self.out_port = out_port
        else:
            self.out_port = 0
        if out_group is not None:
            self.out_group = out_group
        else:
            self.out_group = 0
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if match is not None:
            self.match = match
        else:
            self.match = ofp.match()
        if instructions is not None:
            self.instructions = instructions
        else:
            self.instructions = []
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!Q", self.cookie))
        packed.append(struct.pack("!Q", self.cookie_mask))
        packed.append(struct.pack("!B", self.table_id))
        packed.append(util.pack_fm_cmd(self._command))
        packed.append(struct.pack("!H", self.idle_timeout))
        packed.append(struct.pack("!H", self.hard_timeout))
        packed.append(struct.pack("!H", self.priority))
        packed.append(struct.pack("!L", self.buffer_id))
        packed.append(util.pack_port_no(self.out_port))
        packed.append(struct.pack("!L", self.out_group))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 2)
        packed.append(self.match.pack())
        packed.append(loxi.generic_util.pack_list(self.instructions))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = flow_add()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 14)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.cookie = reader.read("!Q")[0]
        obj.cookie_mask = reader.read("!Q")[0]
        obj.table_id = reader.read("!B")[0]
        __command = util.unpack_fm_cmd(reader)
        assert (__command == 0)
        obj.idle_timeout = reader.read("!H")[0]
        obj.hard_timeout = reader.read("!H")[0]
        obj.priority = reader.read("!H")[0]
        obj.buffer_id = reader.read("!L")[0]
        obj.out_port = util.unpack_port_no(reader)
        obj.out_group = reader.read("!L")[0]
        obj.flags = reader.read("!H")[0]
        reader.skip(2)
        obj.match = ofp.match.unpack(reader)
        obj.instructions = loxi.generic_util.unpack_list(reader, ofp.instruction.instruction.unpack)
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.cookie != other.cookie:
            return False
        if self.cookie_mask != other.cookie_mask:
            return False
        if self.table_id != other.table_id:
            return False
        if self.idle_timeout != other.idle_timeout:
            return False
        if self.hard_timeout != other.hard_timeout:
            return False
        if self.priority != other.priority:
            return False
        if self.buffer_id != other.buffer_id:
            return False
        if self.out_port != other.out_port:
            return False
        if self.out_group != other.out_group:
            return False
        if self.flags != other.flags:
            return False
        if self.match != other.match:
            return False
        if self.instructions != other.instructions:
            return False
        return True

    def pretty_print(self, q):
        q.text("flow_add {")
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
                q.text("cookie = ")
                q.text("%#x" % self.cookie)
                q.text(",")
                q.breakable()
                q.text("cookie_mask = ")
                q.text("%#x" % self.cookie_mask)
                q.text(",")
                q.breakable()
                q.text("table_id = ")
                q.text("%#x" % self.table_id)
                q.text(",")
                q.breakable()
                q.text("idle_timeout = ")
                q.text("%#x" % self.idle_timeout)
                q.text(",")
                q.breakable()
                q.text("hard_timeout = ")
                q.text("%#x" % self.hard_timeout)
                q.text(",")
                q.breakable()
                q.text("priority = ")
                q.text("%#x" % self.priority)
                q.text(",")
                q.breakable()
                q.text("buffer_id = ")
                q.text("%#x" % self.buffer_id)
                q.text(",")
                q.breakable()
                q.text("out_port = ")
                q.text(util.pretty_port(self.out_port))
                q.text(",")
                q.breakable()
                q.text("out_group = ")
                q.text("%#x" % self.out_group)
                q.text(",")
                q.breakable()
                q.text("flags = ")
                q.text("%#x" % self.flags)
                q.text(",")
                q.breakable()
                q.text("match = ")
                q.pp(self.match)
                q.text(",")
                q.breakable()
                q.text("instructions = ")
                q.pp(self.instructions)
            q.breakable()
        q.text('}')


flow_mod.subtypes[0] = flow_add


class flow_delete(flow_mod):
    version = 4
    type = 14
    _command = 3

    def __init__(self, xid=None, cookie=None, cookie_mask=None, table_id=None, idle_timeout=None, hard_timeout=None,
                 priority=None, buffer_id=None, out_port=None, out_group=None, flags=None, match=None,
                 instructions=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if cookie is not None:
            self.cookie = cookie
        else:
            self.cookie = 0
        if cookie_mask is not None:
            self.cookie_mask = cookie_mask
        else:
            self.cookie_mask = 0
        if table_id is not None:
            self.table_id = table_id
        else:
            self.table_id = 0
        if idle_timeout is not None:
            self.idle_timeout = idle_timeout
        else:
            self.idle_timeout = 0
        if hard_timeout is not None:
            self.hard_timeout = hard_timeout
        else:
            self.hard_timeout = 0
        if priority is not None:
            self.priority = priority
        else:
            self.priority = 0
        if buffer_id is not None:
            self.buffer_id = buffer_id
        else:
            self.buffer_id = 0
        if out_port is not None:
            self.out_port = out_port
        else:
            self.out_port = 0
        if out_group is not None:
            self.out_group = out_group
        else:
            self.out_group = 0
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if match is not None:
            self.match = match
        else:
            self.match = ofp.match()
        if instructions is not None:
            self.instructions = instructions
        else:
            self.instructions = []
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!Q", self.cookie))
        packed.append(struct.pack("!Q", self.cookie_mask))
        packed.append(struct.pack("!B", self.table_id))
        packed.append(util.pack_fm_cmd(self._command))
        packed.append(struct.pack("!H", self.idle_timeout))
        packed.append(struct.pack("!H", self.hard_timeout))
        packed.append(struct.pack("!H", self.priority))
        packed.append(struct.pack("!L", self.buffer_id))
        packed.append(util.pack_port_no(self.out_port))
        packed.append(struct.pack("!L", self.out_group))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 2)
        packed.append(self.match.pack())
        packed.append(loxi.generic_util.pack_list(self.instructions))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = flow_delete()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 14)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.cookie = reader.read("!Q")[0]
        obj.cookie_mask = reader.read("!Q")[0]
        obj.table_id = reader.read("!B")[0]
        __command = util.unpack_fm_cmd(reader)
        assert (__command == 3)
        obj.idle_timeout = reader.read("!H")[0]
        obj.hard_timeout = reader.read("!H")[0]
        obj.priority = reader.read("!H")[0]
        obj.buffer_id = reader.read("!L")[0]
        obj.out_port = util.unpack_port_no(reader)
        obj.out_group = reader.read("!L")[0]
        obj.flags = reader.read("!H")[0]
        reader.skip(2)
        obj.match = ofp.match.unpack(reader)
        obj.instructions = loxi.generic_util.unpack_list(reader, ofp.instruction.instruction.unpack)
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.cookie != other.cookie:
            return False
        if self.cookie_mask != other.cookie_mask:
            return False
        if self.table_id != other.table_id:
            return False
        if self.idle_timeout != other.idle_timeout:
            return False
        if self.hard_timeout != other.hard_timeout:
            return False
        if self.priority != other.priority:
            return False
        if self.buffer_id != other.buffer_id:
            return False
        if self.out_port != other.out_port:
            return False
        if self.out_group != other.out_group:
            return False
        if self.flags != other.flags:
            return False
        if self.match != other.match:
            return False
        if self.instructions != other.instructions:
            return False
        return True

    def pretty_print(self, q):
        q.text("flow_delete {")
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
                q.text("cookie = ")
                q.text("%#x" % self.cookie)
                q.text(",")
                q.breakable()
                q.text("cookie_mask = ")
                q.text("%#x" % self.cookie_mask)
                q.text(",")
                q.breakable()
                q.text("table_id = ")
                q.text("%#x" % self.table_id)
                q.text(",")
                q.breakable()
                q.text("idle_timeout = ")
                q.text("%#x" % self.idle_timeout)
                q.text(",")
                q.breakable()
                q.text("hard_timeout = ")
                q.text("%#x" % self.hard_timeout)
                q.text(",")
                q.breakable()
                q.text("priority = ")
                q.text("%#x" % self.priority)
                q.text(",")
                q.breakable()
                q.text("buffer_id = ")
                q.text("%#x" % self.buffer_id)
                q.text(",")
                q.breakable()
                q.text("out_port = ")
                q.text(util.pretty_port(self.out_port))
                q.text(",")
                q.breakable()
                q.text("out_group = ")
                q.text("%#x" % self.out_group)
                q.text(",")
                q.breakable()
                q.text("flags = ")
                q.text("%#x" % self.flags)
                q.text(",")
                q.breakable()
                q.text("match = ")
                q.pp(self.match)
                q.text(",")
                q.breakable()
                q.text("instructions = ")
                q.pp(self.instructions)
            q.breakable()
        q.text('}')


flow_mod.subtypes[3] = flow_delete


class flow_delete_strict(flow_mod):
    version = 4
    type = 14
    _command = 4

    def __init__(self, xid=None, cookie=None, cookie_mask=None, table_id=None, idle_timeout=None, hard_timeout=None,
                 priority=None, buffer_id=None, out_port=None, out_group=None, flags=None, match=None,
                 instructions=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if cookie is not None:
            self.cookie = cookie
        else:
            self.cookie = 0
        if cookie_mask is not None:
            self.cookie_mask = cookie_mask
        else:
            self.cookie_mask = 0
        if table_id is not None:
            self.table_id = table_id
        else:
            self.table_id = 0
        if idle_timeout is not None:
            self.idle_timeout = idle_timeout
        else:
            self.idle_timeout = 0
        if hard_timeout is not None:
            self.hard_timeout = hard_timeout
        else:
            self.hard_timeout = 0
        if priority is not None:
            self.priority = priority
        else:
            self.priority = 0
        if buffer_id is not None:
            self.buffer_id = buffer_id
        else:
            self.buffer_id = 0
        if out_port is not None:
            self.out_port = out_port
        else:
            self.out_port = 0
        if out_group is not None:
            self.out_group = out_group
        else:
            self.out_group = 0
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if match is not None:
            self.match = match
        else:
            self.match = ofp.match()
        if instructions is not None:
            self.instructions = instructions
        else:
            self.instructions = []
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!Q", self.cookie))
        packed.append(struct.pack("!Q", self.cookie_mask))
        packed.append(struct.pack("!B", self.table_id))
        packed.append(util.pack_fm_cmd(self._command))
        packed.append(struct.pack("!H", self.idle_timeout))
        packed.append(struct.pack("!H", self.hard_timeout))
        packed.append(struct.pack("!H", self.priority))
        packed.append(struct.pack("!L", self.buffer_id))
        packed.append(util.pack_port_no(self.out_port))
        packed.append(struct.pack("!L", self.out_group))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 2)
        packed.append(self.match.pack())
        packed.append(loxi.generic_util.pack_list(self.instructions))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = flow_delete_strict()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 14)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.cookie = reader.read("!Q")[0]
        obj.cookie_mask = reader.read("!Q")[0]
        obj.table_id = reader.read("!B")[0]
        __command = util.unpack_fm_cmd(reader)
        assert (__command == 4)
        obj.idle_timeout = reader.read("!H")[0]
        obj.hard_timeout = reader.read("!H")[0]
        obj.priority = reader.read("!H")[0]
        obj.buffer_id = reader.read("!L")[0]
        obj.out_port = util.unpack_port_no(reader)
        obj.out_group = reader.read("!L")[0]
        obj.flags = reader.read("!H")[0]
        reader.skip(2)
        obj.match = ofp.match.unpack(reader)
        obj.instructions = loxi.generic_util.unpack_list(reader, ofp.instruction.instruction.unpack)
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.cookie != other.cookie:
            return False
        if self.cookie_mask != other.cookie_mask:
            return False
        if self.table_id != other.table_id:
            return False
        if self.idle_timeout != other.idle_timeout:
            return False
        if self.hard_timeout != other.hard_timeout:
            return False
        if self.priority != other.priority:
            return False
        if self.buffer_id != other.buffer_id:
            return False
        if self.out_port != other.out_port:
            return False
        if self.out_group != other.out_group:
            return False
        if self.flags != other.flags:
            return False
        if self.match != other.match:
            return False
        if self.instructions != other.instructions:
            return False
        return True

    def pretty_print(self, q):
        q.text("flow_delete_strict {")
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
                q.text("cookie = ")
                q.text("%#x" % self.cookie)
                q.text(",")
                q.breakable()
                q.text("cookie_mask = ")
                q.text("%#x" % self.cookie_mask)
                q.text(",")
                q.breakable()
                q.text("table_id = ")
                q.text("%#x" % self.table_id)
                q.text(",")
                q.breakable()
                q.text("idle_timeout = ")
                q.text("%#x" % self.idle_timeout)
                q.text(",")
                q.breakable()
                q.text("hard_timeout = ")
                q.text("%#x" % self.hard_timeout)
                q.text(",")
                q.breakable()
                q.text("priority = ")
                q.text("%#x" % self.priority)
                q.text(",")
                q.breakable()
                q.text("buffer_id = ")
                q.text("%#x" % self.buffer_id)
                q.text(",")
                q.breakable()
                q.text("out_port = ")
                q.text(util.pretty_port(self.out_port))
                q.text(",")
                q.breakable()
                q.text("out_group = ")
                q.text("%#x" % self.out_group)
                q.text(",")
                q.breakable()
                q.text("flags = ")
                q.text("%#x" % self.flags)
                q.text(",")
                q.breakable()
                q.text("match = ")
                q.pp(self.match)
                q.text(",")
                q.breakable()
                q.text("instructions = ")
                q.pp(self.instructions)
            q.breakable()
        q.text('}')


flow_mod.subtypes[4] = flow_delete_strict


class flow_mod_failed_error_msg(error_msg):
    version = 4
    type = 1
    err_type = 5

    def __init__(self, xid=None, code=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if code is not None:
            self.code = code
        else:
            self.code = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        packed.append(struct.pack("!H", self.code))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = flow_mod_failed_error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _err_type = reader.read("!H")[0]
        assert (_err_type == 5)
        obj.code = reader.read("!H")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.code != other.code:
            return False
        if self.data != other.data:
            return False
        return True

    def pretty_print(self, q):
        q.text("flow_mod_failed_error_msg {")
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
                q.text("code = ")
                q.text("%#x" % self.code)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


error_msg.subtypes[5] = flow_mod_failed_error_msg


class flow_modify(flow_mod):
    version = 4
    type = 14
    _command = 1

    def __init__(self, xid=None, cookie=None, cookie_mask=None, table_id=None, idle_timeout=None, hard_timeout=None,
                 priority=None, buffer_id=None, out_port=None, out_group=None, flags=None, match=None,
                 instructions=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if cookie is not None:
            self.cookie = cookie
        else:
            self.cookie = 0
        if cookie_mask is not None:
            self.cookie_mask = cookie_mask
        else:
            self.cookie_mask = 0
        if table_id is not None:
            self.table_id = table_id
        else:
            self.table_id = 0
        if idle_timeout is not None:
            self.idle_timeout = idle_timeout
        else:
            self.idle_timeout = 0
        if hard_timeout is not None:
            self.hard_timeout = hard_timeout
        else:
            self.hard_timeout = 0
        if priority is not None:
            self.priority = priority
        else:
            self.priority = 0
        if buffer_id is not None:
            self.buffer_id = buffer_id
        else:
            self.buffer_id = 0
        if out_port is not None:
            self.out_port = out_port
        else:
            self.out_port = 0
        if out_group is not None:
            self.out_group = out_group
        else:
            self.out_group = 0
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if match is not None:
            self.match = match
        else:
            self.match = ofp.match()
        if instructions is not None:
            self.instructions = instructions
        else:
            self.instructions = []
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!Q", self.cookie))
        packed.append(struct.pack("!Q", self.cookie_mask))
        packed.append(struct.pack("!B", self.table_id))
        packed.append(util.pack_fm_cmd(self._command))
        packed.append(struct.pack("!H", self.idle_timeout))
        packed.append(struct.pack("!H", self.hard_timeout))
        packed.append(struct.pack("!H", self.priority))
        packed.append(struct.pack("!L", self.buffer_id))
        packed.append(util.pack_port_no(self.out_port))
        packed.append(struct.pack("!L", self.out_group))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 2)
        packed.append(self.match.pack())
        packed.append(loxi.generic_util.pack_list(self.instructions))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = flow_modify()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 14)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.cookie = reader.read("!Q")[0]
        obj.cookie_mask = reader.read("!Q")[0]
        obj.table_id = reader.read("!B")[0]
        __command = util.unpack_fm_cmd(reader)
        assert (__command == 1)
        obj.idle_timeout = reader.read("!H")[0]
        obj.hard_timeout = reader.read("!H")[0]
        obj.priority = reader.read("!H")[0]
        obj.buffer_id = reader.read("!L")[0]
        obj.out_port = util.unpack_port_no(reader)
        obj.out_group = reader.read("!L")[0]
        obj.flags = reader.read("!H")[0]
        reader.skip(2)
        obj.match = ofp.match.unpack(reader)
        obj.instructions = loxi.generic_util.unpack_list(reader, ofp.instruction.instruction.unpack)
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.cookie != other.cookie: return False
        if self.cookie_mask != other.cookie_mask: return False
        if self.table_id != other.table_id: return False
        if self.idle_timeout != other.idle_timeout: return False
        if self.hard_timeout != other.hard_timeout: return False
        if self.priority != other.priority: return False
        if self.buffer_id != other.buffer_id: return False
        if self.out_port != other.out_port: return False
        if self.out_group != other.out_group: return False
        if self.flags != other.flags: return False
        if self.match != other.match: return False
        if self.instructions != other.instructions: return False
        return True

    def pretty_print(self, q):
        q.text("flow_modify {")
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
                q.text("cookie = ")
                q.text("%#x" % self.cookie)
                q.text(",")
                q.breakable()
                q.text("cookie_mask = ")
                q.text("%#x" % self.cookie_mask)
                q.text(",")
                q.breakable()
                q.text("table_id = ")
                q.text("%#x" % self.table_id)
                q.text(",")
                q.breakable()
                q.text("idle_timeout = ")
                q.text("%#x" % self.idle_timeout)
                q.text(",")
                q.breakable()
                q.text("hard_timeout = ")
                q.text("%#x" % self.hard_timeout)
                q.text(",")
                q.breakable()
                q.text("priority = ")
                q.text("%#x" % self.priority)
                q.text(",")
                q.breakable()
                q.text("buffer_id = ")
                q.text("%#x" % self.buffer_id)
                q.text(",")
                q.breakable()
                q.text("out_port = ")
                q.text(util.pretty_port(self.out_port))
                q.text(",")
                q.breakable()
                q.text("out_group = ")
                q.text("%#x" % self.out_group)
                q.text(",")
                q.breakable()
                q.text("flags = ")
                q.text("%#x" % self.flags)
                q.text(",")
                q.breakable()
                q.text("match = ")
                q.pp(self.match)
                q.text(",")
                q.breakable()
                q.text("instructions = ")
                q.pp(self.instructions)
            q.breakable()
        q.text('}')


flow_mod.subtypes[1] = flow_modify


class flow_modify_strict(flow_mod):
    version = 4
    type = 14
    _command = 2

    def __init__(self, xid=None, cookie=None, cookie_mask=None, table_id=None, idle_timeout=None, hard_timeout=None,
                 priority=None, buffer_id=None, out_port=None, out_group=None, flags=None, match=None,
                 instructions=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if cookie is not None:
            self.cookie = cookie
        else:
            self.cookie = 0
        if cookie_mask is not None:
            self.cookie_mask = cookie_mask
        else:
            self.cookie_mask = 0
        if table_id is not None:
            self.table_id = table_id
        else:
            self.table_id = 0
        if idle_timeout is not None:
            self.idle_timeout = idle_timeout
        else:
            self.idle_timeout = 0
        if hard_timeout is not None:
            self.hard_timeout = hard_timeout
        else:
            self.hard_timeout = 0
        if priority is not None:
            self.priority = priority
        else:
            self.priority = 0
        if buffer_id is not None:
            self.buffer_id = buffer_id
        else:
            self.buffer_id = 0
        if out_port is not None:
            self.out_port = out_port
        else:
            self.out_port = 0
        if out_group is not None:
            self.out_group = out_group
        else:
            self.out_group = 0
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if match is not None:
            self.match = match
        else:
            self.match = ofp.match()
        if instructions is not None:
            self.instructions = instructions
        else:
            self.instructions = []
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!Q", self.cookie))
        packed.append(struct.pack("!Q", self.cookie_mask))
        packed.append(struct.pack("!B", self.table_id))
        packed.append(util.pack_fm_cmd(self._command))
        packed.append(struct.pack("!H", self.idle_timeout))
        packed.append(struct.pack("!H", self.hard_timeout))
        packed.append(struct.pack("!H", self.priority))
        packed.append(struct.pack("!L", self.buffer_id))
        packed.append(util.pack_port_no(self.out_port))
        packed.append(struct.pack("!L", self.out_group))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 2)
        packed.append(self.match.pack())
        packed.append(loxi.generic_util.pack_list(self.instructions))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = flow_modify_strict()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 14)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.cookie = reader.read("!Q")[0]
        obj.cookie_mask = reader.read("!Q")[0]
        obj.table_id = reader.read("!B")[0]
        __command = util.unpack_fm_cmd(reader)
        assert (__command == 2)
        obj.idle_timeout = reader.read("!H")[0]
        obj.hard_timeout = reader.read("!H")[0]
        obj.priority = reader.read("!H")[0]
        obj.buffer_id = reader.read("!L")[0]
        obj.out_port = util.unpack_port_no(reader)
        obj.out_group = reader.read("!L")[0]
        obj.flags = reader.read("!H")[0]
        reader.skip(2)
        obj.match = ofp.match.unpack(reader)
        obj.instructions = loxi.generic_util.unpack_list(reader, ofp.instruction.instruction.unpack)
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.cookie != other.cookie: return False
        if self.cookie_mask != other.cookie_mask: return False
        if self.table_id != other.table_id: return False
        if self.idle_timeout != other.idle_timeout: return False
        if self.hard_timeout != other.hard_timeout: return False
        if self.priority != other.priority: return False
        if self.buffer_id != other.buffer_id: return False
        if self.out_port != other.out_port: return False
        if self.out_group != other.out_group: return False
        if self.flags != other.flags: return False
        if self.match != other.match: return False
        if self.instructions != other.instructions: return False
        return True

    def pretty_print(self, q):
        q.text("flow_modify_strict {")
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
                q.text("cookie = ")
                q.text("%#x" % self.cookie)
                q.text(",")
                q.breakable()
                q.text("cookie_mask = ")
                q.text("%#x" % self.cookie_mask)
                q.text(",")
                q.breakable()
                q.text("table_id = ")
                q.text("%#x" % self.table_id)
                q.text(",")
                q.breakable()
                q.text("idle_timeout = ")
                q.text("%#x" % self.idle_timeout)
                q.text(",")
                q.breakable()
                q.text("hard_timeout = ")
                q.text("%#x" % self.hard_timeout)
                q.text(",")
                q.breakable()
                q.text("priority = ")
                q.text("%#x" % self.priority)
                q.text(",")
                q.breakable()
                q.text("buffer_id = ")
                q.text("%#x" % self.buffer_id)
                q.text(",")
                q.breakable()
                q.text("out_port = ")
                q.text(util.pretty_port(self.out_port))
                q.text(",")
                q.breakable()
                q.text("out_group = ")
                q.text("%#x" % self.out_group)
                q.text(",")
                q.breakable()
                q.text("flags = ")
                q.text("%#x" % self.flags)
                q.text(",")
                q.breakable()
                q.text("match = ")
                q.pp(self.match)
                q.text(",")
                q.breakable()
                q.text("instructions = ")
                q.pp(self.instructions)
            q.breakable()
        q.text('}')


flow_mod.subtypes[2] = flow_modify_strict


class flow_removed(fuzzer):
    version = 4
    type = 11

    def __init__(self, xid=None, cookie=None, priority=None, reason=None, table_id=None, duration_sec=None,
                 duration_nsec=None, idle_timeout=None, hard_timeout=None, packet_count=None, byte_count=None,
                 match=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if cookie is not None:
            self.cookie = cookie
        else:
            self.cookie = 0
        if priority is not None:
            self.priority = priority
        else:
            self.priority = 0
        if reason is not None:
            self.reason = reason
        else:
            self.reason = 0
        if table_id is not None:
            self.table_id = table_id
        else:
            self.table_id = 0
        if duration_sec is not None:
            self.duration_sec = duration_sec
        else:
            self.duration_sec = 0
        if duration_nsec is not None:
            self.duration_nsec = duration_nsec
        else:
            self.duration_nsec = 0
        if idle_timeout is not None:
            self.idle_timeout = idle_timeout
        else:
            self.idle_timeout = 0
        if hard_timeout is not None:
            self.hard_timeout = hard_timeout
        else:
            self.hard_timeout = 0
        if packet_count is not None:
            self.packet_count = packet_count
        else:
            self.packet_count = 0
        if byte_count is not None:
            self.byte_count = byte_count
        else:
            self.byte_count = 0
        if match is not None:
            self.match = match
        else:
            self.match = ofp.match()
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!Q", self.cookie))
        packed.append(struct.pack("!H", self.priority))
        packed.append(struct.pack("!B", self.reason))
        packed.append(struct.pack("!B", self.table_id))
        packed.append(struct.pack("!L", self.duration_sec))
        packed.append(struct.pack("!L", self.duration_nsec))
        packed.append(struct.pack("!H", self.idle_timeout))
        packed.append(struct.pack("!H", self.hard_timeout))
        packed.append(struct.pack("!Q", self.packet_count))
        packed.append(struct.pack("!Q", self.byte_count))
        packed.append(self.match.pack())
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = flow_removed()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 11)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.cookie = reader.read("!Q")[0]
        obj.priority = reader.read("!H")[0]
        obj.reason = reader.read("!B")[0]
        obj.table_id = reader.read("!B")[0]
        obj.duration_sec = reader.read("!L")[0]
        obj.duration_nsec = reader.read("!L")[0]
        obj.idle_timeout = reader.read("!H")[0]
        obj.hard_timeout = reader.read("!H")[0]
        obj.packet_count = reader.read("!Q")[0]
        obj.byte_count = reader.read("!Q")[0]
        obj.match = ofp.match.unpack(reader)
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.cookie != other.cookie:
            return False
        if self.priority != other.priority:
            return False
        if self.reason != other.reason:
            return False
        if self.table_id != other.table_id:
            return False
        if self.duration_sec != other.duration_sec:
            return False
        if self.duration_nsec != other.duration_nsec:
            return False
        if self.idle_timeout != other.idle_timeout:
            return False
        if self.hard_timeout != other.hard_timeout:
            return False
        if self.packet_count != other.packet_count:
            return False
        if self.byte_count != other.byte_count:
            return False
        if self.match != other.match:
            return False
        return True

    def pretty_print(self, q):
        q.text("flow_removed {")
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
                q.text("cookie = ")
                q.text("%#x" % self.cookie)
                q.text(",")
                q.breakable()
                q.text("priority = ")
                q.text("%#x" % self.priority)
                q.text(",")
                q.breakable()
                q.text("reason = ")
                q.text("%#x" % self.reason)
                q.text(",")
                q.breakable()
                q.text("table_id = ")
                q.text("%#x" % self.table_id)
                q.text(",")
                q.breakable()
                q.text("duration_sec = ")
                q.text("%#x" % self.duration_sec)
                q.text(",")
                q.breakable()
                q.text("duration_nsec = ")
                q.text("%#x" % self.duration_nsec)
                q.text(",")
                q.breakable()
                q.text("idle_timeout = ")
                q.text("%#x" % self.idle_timeout)
                q.text(",")
                q.breakable()
                q.text("hard_timeout = ")
                q.text("%#x" % self.hard_timeout)
                q.text(",")
                q.breakable()
                q.text("packet_count = ")
                q.text("%#x" % self.packet_count)
                q.text(",")
                q.breakable()
                q.text("byte_count = ")
                q.text("%#x" % self.byte_count)
                q.text(",")
                q.breakable()
                q.text("match = ")
                q.pp(self.match)
            q.breakable()
        q.text('}')


fuzzer.subtypes[11] = flow_removed


class flow_stats_request(stats_request):
    version = 4
    type = 18
    stats_type = 1

    def __init__(self, xid=None, flags=None, table_id=None, out_port=None, out_group=None, cookie=None,
                 cookie_mask=None, match=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if table_id is not None:
            self.table_id = table_id
        else:
            self.table_id = 0
        if out_port is not None:
            self.out_port = out_port
        else:
            self.out_port = 0
        if out_group is not None:
            self.out_group = out_group
        else:
            self.out_group = 0
        if cookie is not None:
            self.cookie = cookie
        else:
            self.cookie = 0
        if cookie_mask is not None:
            self.cookie_mask = cookie_mask
        else:
            self.cookie_mask = 0
        if match is not None:
            self.match = match
        else:
            self.match = ofp.match()
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        packed.append(struct.pack("!B", self.table_id))
        packed.append('\x00' * 3)
        packed.append(util.pack_port_no(self.out_port))
        packed.append(struct.pack("!L", self.out_group))
        packed.append('\x00' * 4)
        packed.append(struct.pack("!Q", self.cookie))
        packed.append(struct.pack("!Q", self.cookie_mask))
        packed.append(self.match.pack())
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = flow_stats_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _stats_type = reader.read("!H")[0]
        assert (_stats_type == 1)
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        obj.table_id = reader.read("!B")[0]
        reader.skip(3)
        obj.out_port = util.unpack_port_no(reader)
        obj.out_group = reader.read("!L")[0]
        reader.skip(4)
        obj.cookie = reader.read("!Q")[0]
        obj.cookie_mask = reader.read("!Q")[0]
        obj.match = ofp.match.unpack(reader)
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.flags != other.flags: return False
        if self.table_id != other.table_id: return False
        if self.out_port != other.out_port: return False
        if self.out_group != other.out_group: return False
        if self.cookie != other.cookie: return False
        if self.cookie_mask != other.cookie_mask: return False
        if self.match != other.match: return False
        return True

    def pretty_print(self, q):
        q.text("flow_stats_request {")
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
                q.text(",")
                q.breakable()
                q.text("table_id = ")
                q.text("%#x" % self.table_id)
                q.text(",")
                q.breakable()
                q.text("out_port = ")
                q.text(util.pretty_port(self.out_port))
                q.text(",")
                q.breakable()
                q.text("out_group = ")
                q.text("%#x" % self.out_group)
                q.text(",")
                q.breakable()
                q.text("cookie = ")
                q.text("%#x" % self.cookie)
                q.text(",")
                q.breakable()
                q.text("cookie_mask = ")
                q.text("%#x" % self.cookie_mask)
                q.text(",")
                q.breakable()
                q.text("match = ")
                q.pp(self.match)
            q.breakable()
        q.text('}')


stats_request.subtypes[1] = flow_stats_request


class get_config_request(fuzzer):
    version = 4
    type = 7

    def __init__(self, xid=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = get_config_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 7)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        return True

    def pretty_print(self, q):
        q.text("get_config_request {")
        with q.group():
            with q.indent(2):
                q.breakable()
                q.text("xid = ")
                if self.xid is not None:
                    q.text("%#x" % self.xid)
                else:
                    q.text('None')
            q.breakable()
        q.text('}')


fuzzer.subtypes[7] = get_config_request


class group_mod(fuzzer):
    subtypes = {}

    version = 4
    type = 15

    def __init__(self, xid=None, command=None, group_type=None, group_id=None, buckets=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if command is not None:
            self.command = command
        else:
            self.command = 0
        if group_type is not None:
            self.group_type = group_type
        else:
            self.group_type = 0
        if group_id is not None:
            self.group_id = group_id
        else:
            self.group_id = 0
        if buckets is not None:
            self.buckets = buckets
        else:
            self.buckets = []
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.command))
        packed.append(struct.pack("!B", self.group_type))
        packed.append('\x00' * 1)
        packed.append(struct.pack("!L", self.group_id))
        packed.append(loxi.generic_util.pack_list(self.buckets))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        subtype, = reader.peek('!H', 8)
        subclass = group_mod.subtypes.get(subtype)
        if subclass:
            return subclass.unpack(reader)

        obj = group_mod()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 15)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.command = reader.read("!H")[0]
        obj.group_type = reader.read("!B")[0]
        reader.skip(1)
        obj.group_id = reader.read("!L")[0]
        obj.buckets = loxi.generic_util.unpack_list(reader, ofp.common.bucket.unpack)
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.command != other.command:
            return False
        if self.group_type != other.group_type:
            return False
        if self.group_id != other.group_id:
            return False
        if self.buckets != other.buckets:
            return False
        return True

    def pretty_print(self, q):
        q.text("group_mod {")
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
                q.text("group_type = ")
                q.text("%#x" % self.group_type)
                q.text(",")
                q.breakable()
                q.text("group_id = ")
                q.text("%#x" % self.group_id)
                q.text(",")
                q.breakable()
                q.text("buckets = ")
                q.pp(self.buckets)
            q.breakable()
        q.text('}')


fuzzer.subtypes[15] = group_mod


class group_add(group_mod):
    version = 4
    type = 15
    command = 0

    def __init__(self, xid=None, group_type=None, group_id=None, buckets=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if group_type is not None:
            self.group_type = group_type
        else:
            self.group_type = 0
        if group_id is not None:
            self.group_id = group_id
        else:
            self.group_id = 0
        if buckets is not None:
            self.buckets = buckets
        else:
            self.buckets = []
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.command))
        packed.append(struct.pack("!B", self.group_type))
        packed.append('\x00' * 1)
        packed.append(struct.pack("!L", self.group_id))
        packed.append(loxi.generic_util.pack_list(self.buckets))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = group_add()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 15)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _command = reader.read("!H")[0]
        assert (_command == 0)
        obj.group_type = reader.read("!B")[0]
        reader.skip(1)
        obj.group_id = reader.read("!L")[0]
        obj.buckets = loxi.generic_util.unpack_list(reader, ofp.common.bucket.unpack)
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.group_type != other.group_type: return False
        if self.group_id != other.group_id: return False
        if self.buckets != other.buckets: return False
        return True

    def pretty_print(self, q):
        q.text("group_add {")
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
                q.text("group_type = ")
                q.text("%#x" % self.group_type)
                q.text(",")
                q.breakable()
                q.text("group_id = ")
                q.text("%#x" % self.group_id)
                q.text(",")
                q.breakable()
                q.text("buckets = ")
                q.pp(self.buckets)
            q.breakable()
        q.text('}')


group_mod.subtypes[0] = group_add


class group_delete(group_mod):
    version = 4
    type = 15
    command = 2

    def __init__(self, xid=None, group_type=None, group_id=None, buckets=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if group_type is not None:
            self.group_type = group_type
        else:
            self.group_type = 0
        if group_id is not None:
            self.group_id = group_id
        else:
            self.group_id = 0
        if buckets is not None:
            self.buckets = buckets
        else:
            self.buckets = []
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.command))
        packed.append(struct.pack("!B", self.group_type))
        packed.append('\x00' * 1)
        packed.append(struct.pack("!L", self.group_id))
        packed.append(loxi.generic_util.pack_list(self.buckets))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = group_delete()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 15)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _command = reader.read("!H")[0]
        assert (_command == 2)
        obj.group_type = reader.read("!B")[0]
        reader.skip(1)
        obj.group_id = reader.read("!L")[0]
        obj.buckets = loxi.generic_util.unpack_list(reader, ofp.common.bucket.unpack)
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.group_type != other.group_type: return False
        if self.group_id != other.group_id: return False
        if self.buckets != other.buckets: return False
        return True

    def pretty_print(self, q):
        q.text("group_delete {")
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
                q.text("group_type = ")
                q.text("%#x" % self.group_type)
                q.text(",")
                q.breakable()
                q.text("group_id = ")
                q.text("%#x" % self.group_id)
                q.text(",")
                q.breakable()
                q.text("buckets = ")
                q.pp(self.buckets)
            q.breakable()
        q.text('}')


group_mod.subtypes[2] = group_delete


class group_desc_stats_request(stats_request):
    version = 4
    type = 18
    stats_type = 7

    def __init__(self, xid=None, flags=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = group_desc_stats_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _stats_type = reader.read("!H")[0]
        assert (_stats_type == 7)
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.flags != other.flags: return False
        return True

    def pretty_print(self, q):
        q.text("group_desc_stats_request {")
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


stats_request.subtypes[7] = group_desc_stats_request


class group_features_stats_request(stats_request):
    version = 4
    type = 18
    stats_type = 8

    def __init__(self, xid=None, flags=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = group_features_stats_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _stats_type = reader.read("!H")[0]
        assert (_stats_type == 8)
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.flags != other.flags: return False
        return True

    def pretty_print(self, q):
        q.text("group_features_stats_request {")
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


stats_request.subtypes[8] = group_features_stats_request


class group_mod_failed_error_msg(error_msg):
    version = 4
    type = 1
    err_type = 6

    def __init__(self, xid=None, code=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if code is not None:
            self.code = code
        else:
            self.code = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        packed.append(struct.pack("!H", self.code))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = group_mod_failed_error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _err_type = reader.read("!H")[0]
        assert (_err_type == 6)
        obj.code = reader.read("!H")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.code != other.code: return False
        if self.data != other.data: return False
        return True

    def pretty_print(self, q):
        q.text("group_mod_failed_error_msg {")
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
                q.text("code = ")
                q.text("%#x" % self.code)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


error_msg.subtypes[6] = group_mod_failed_error_msg


class group_modify(group_mod):
    version = 4
    type = 15
    command = 1

    def __init__(self, xid=None, group_type=None, group_id=None, buckets=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if group_type is not None:
            self.group_type = group_type
        else:
            self.group_type = 0
        if group_id is not None:
            self.group_id = group_id
        else:
            self.group_id = 0
        if buckets is not None:
            self.buckets = buckets
        else:
            self.buckets = []
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.command))
        packed.append(struct.pack("!B", self.group_type))
        packed.append('\x00' * 1)
        packed.append(struct.pack("!L", self.group_id))
        packed.append(loxi.generic_util.pack_list(self.buckets))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = group_modify()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 15)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _command = reader.read("!H")[0]
        assert (_command == 1)
        obj.group_type = reader.read("!B")[0]
        reader.skip(1)
        obj.group_id = reader.read("!L")[0]
        obj.buckets = loxi.generic_util.unpack_list(reader, ofp.common.bucket.unpack)
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.group_type != other.group_type:
            return False
        if self.group_id != other.group_id:
            return False
        if self.buckets != other.buckets:
            return False
        return True

    def pretty_print(self, q):
        q.text("group_modify {")
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
                q.text("group_type = ")
                q.text("%#x" % self.group_type)
                q.text(",")
                q.breakable()
                q.text("group_id = ")
                q.text("%#x" % self.group_id)
                q.text(",")
                q.breakable()
                q.text("buckets = ")
                q.pp(self.buckets)
            q.breakable()
        q.text('}')


group_mod.subtypes[1] = group_modify


class group_stats_request(stats_request):
    version = 4
    type = 18
    stats_type = 6

    def __init__(self, xid=None, flags=None, group_id=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if group_id is not None:
            self.group_id = group_id
        else:
            self.group_id = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        packed.append(struct.pack("!L", self.group_id))
        packed.append('\x00' * 4)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = group_stats_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _stats_type = reader.read("!H")[0]
        assert (_stats_type == 6)
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        obj.group_id = reader.read("!L")[0]
        reader.skip(4)
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.flags != other.flags:
            return False
        if self.group_id != other.group_id:
            return False
        return True

    def pretty_print(self, q):
        q.text("group_stats_request {")
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
                q.text(",")
                q.breakable()
                q.text("group_id = ")
                q.text("%#x" % self.group_id)
            q.breakable()
        q.text('}')


stats_request.subtypes[6] = group_stats_request


class hello(fuzzer):
    version = 4
    type = 0

    def __init__(self, xid=None, elements=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if elements is not None:
            self.elements = elements
        else:
            self.elements = []
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(loxi.generic_util.pack_list(self.elements))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = hello()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 0)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.elements = loxi.generic_util.unpack_list(reader, ofp.common.hello_elem.unpack)
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.elements != other.elements: return False
        return True

    def pretty_print(self, q):
        q.text("hello {")
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
                q.text("elements = ")
                q.pp(self.elements)
            q.breakable()
        q.text('}')


fuzzer.subtypes[0] = hello


class hello_failed_error_msg(error_msg):
    version = 4
    type = 1
    err_type = 0

    def __init__(self, xid=None, code=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if code is not None:
            self.code = code
        else:
            self.code = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        packed.append(struct.pack("!H", self.code))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = hello_failed_error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _err_type = reader.read("!H")[0]
        assert (_err_type == 0)
        obj.code = reader.read("!H")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.code != other.code: return False
        if self.data != other.data: return False
        return True

    def pretty_print(self, q):
        q.text("hello_failed_error_msg {")
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
                q.text("code = ")
                q.text("%#x" % self.code)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


error_msg.subtypes[0] = hello_failed_error_msg


class meter_config_stats_request(stats_request):
    version = 4
    type = 18
    stats_type = 10

    def __init__(self, xid=None, flags=None, meter_id=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if meter_id is not None:
            self.meter_id = meter_id
        else:
            self.meter_id = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        packed.append(struct.pack("!L", self.meter_id))
        packed.append('\x00' * 4)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = meter_config_stats_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _stats_type = reader.read("!H")[0]
        assert (_stats_type == 10)
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        obj.meter_id = reader.read("!L")[0]
        reader.skip(4)
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.flags != other.flags:
            return False
        if self.meter_id != other.meter_id:
            return False
        return True

    def pretty_print(self, q):
        q.text("meter_config_stats_request {")
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
                q.text(",")
                q.breakable()
                q.text("meter_id = ")
                q.text("%#x" % self.meter_id)
            q.breakable()
        q.text('}')


stats_request.subtypes[10] = meter_config_stats_request


class meter_features_stats_request(stats_request):
    version = 4
    type = 18
    stats_type = 11

    def __init__(self, xid=None, flags=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = meter_features_stats_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _stats_type = reader.read("!H")[0]
        assert (_stats_type == 11)
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.flags != other.flags:
            return False
        return True

    def pretty_print(self, q):
        q.text("meter_features_stats_request {")
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


stats_request.subtypes[11] = meter_features_stats_request


class meter_mod(fuzzer):
    version = 4
    type = 29

    def __init__(self, xid=None, command=None, flags=None, meter_id=None, meters=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if command is not None:
            self.command = command
        else:
            self.command = 0
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if meter_id is not None:
            self.meter_id = meter_id
        else:
            self.meter_id = 0
        if meters is not None:
            self.meters = meters
        else:
            self.meters = []
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.command))
        packed.append(struct.pack("!H", self.flags))
        packed.append(struct.pack("!L", self.meter_id))
        packed.append(loxi.generic_util.pack_list(self.meters))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = meter_mod()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 29)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.command = reader.read("!H")[0]
        obj.flags = reader.read("!H")[0]
        obj.meter_id = reader.read("!L")[0]
        obj.meters = loxi.generic_util.unpack_list(reader, ofp.meter_band.meter_band.unpack)
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.command != other.command: return False
        if self.flags != other.flags: return False
        if self.meter_id != other.meter_id: return False
        if self.meters != other.meters: return False
        return True

    def pretty_print(self, q):
        q.text("meter_mod {")
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
                q.text("command = ")
                q.text("%#x" % self.command)
                q.text(",")
                q.breakable()
                q.text("flags = ")
                q.text("%#x" % self.flags)
                q.text(",")
                q.breakable()
                q.text("meter_id = ")
                q.text("%#x" % self.meter_id)
                q.text(",")
                q.breakable()
                q.text("meters = ")
                q.pp(self.meters)
            q.breakable()
        q.text('}')


fuzzer.subtypes[29] = meter_mod


class meter_mod_failed_error_msg(error_msg):
    version = 4
    type = 1
    err_type = 12

    def __init__(self, xid=None, code=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if code is not None:
            self.code = code
        else:
            self.code = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        packed.append(struct.pack("!H", self.code))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = meter_mod_failed_error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _err_type = reader.read("!H")[0]
        assert (_err_type == 12)
        obj.code = reader.read("!H")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.code != other.code: return False
        if self.data != other.data: return False
        return True

    def pretty_print(self, q):
        q.text("meter_mod_failed_error_msg {")
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
                q.text("code = ")
                q.text("%#x" % self.code)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


error_msg.subtypes[12] = meter_mod_failed_error_msg


class meter_stats_request(stats_request):
    version = 4
    type = 18
    stats_type = 9

    def __init__(self, xid=None, flags=None, meter_id=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if meter_id is not None:
            self.meter_id = meter_id
        else:
            self.meter_id = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        packed.append(struct.pack("!L", self.meter_id))
        packed.append('\x00' * 4)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = meter_stats_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _stats_type = reader.read("!H")[0]
        assert (_stats_type == 9)
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        obj.meter_id = reader.read("!L")[0]
        reader.skip(4)
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.flags != other.flags: return False
        if self.meter_id != other.meter_id: return False
        return True

    def pretty_print(self, q):
        q.text("meter_stats_request {")
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
                q.text(",")
                q.breakable()
                q.text("meter_id = ")
                q.text("%#x" % self.meter_id)
            q.breakable()
        q.text('}')


stats_request.subtypes[9] = meter_stats_request


class nicira_header(experimenter):
    subtypes = {}

    version = 4
    type = 4
    experimenter = 8992

    def __init__(self, xid=None, subtype=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if subtype is not None:
            self.subtype = subtype
        else:
            self.subtype = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!L", self.experimenter))
        packed.append(struct.pack("!L", self.subtype))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        subtype, = reader.peek('!L', 12)
        subclass = nicira_header.subtypes.get(subtype)
        if subclass:
            return subclass.unpack(reader)

        obj = nicira_header()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 4)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _experimenter = reader.read("!L")[0]
        assert (_experimenter == 8992)
        obj.subtype = reader.read("!L")[0]
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.subtype != other.subtype: return False
        return True

    def pretty_print(self, q):
        q.text("nicira_header {")
        with q.group():
            with q.indent(2):
                q.breakable()
                q.text("xid = ")
                if self.xid is not None:
                    q.text("%#x" % self.xid)
                else:
                    q.text('None')
            q.breakable()
        q.text('}')


experimenter.subtypes[8992] = nicira_header


class packet_in(fuzzer):
    version = 4
    type = 10

    def __init__(self, xid=None, buffer_id=None, total_len=None, reason=None, table_id=None, cookie=None, match=None,
                 data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if buffer_id is not None:
            self.buffer_id = buffer_id
        else:
            self.buffer_id = 0
        if total_len is not None:
            self.total_len = total_len
        else:
            self.total_len = 0
        if reason is not None:
            self.reason = reason
        else:
            self.reason = 0
        if table_id is not None:
            self.table_id = table_id
        else:
            self.table_id = 0
        if cookie is not None:
            self.cookie = cookie
        else:
            self.cookie = 0
        if match is not None:
            self.match = match
        else:
            self.match = ofp.match()
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!L", self.buffer_id))
        packed.append(struct.pack("!H", self.total_len))
        packed.append(struct.pack("!B", self.reason))
        packed.append(struct.pack("!B", self.table_id))
        packed.append(struct.pack("!Q", self.cookie))
        packed.append(self.match.pack())
        packed.append('\x00' * 2)
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = packet_in()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 10)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.buffer_id = reader.read("!L")[0]
        obj.total_len = reader.read("!H")[0]
        obj.reason = reader.read("!B")[0]
        obj.table_id = reader.read("!B")[0]
        obj.cookie = reader.read("!Q")[0]
        obj.match = ofp.match.unpack(reader)
        reader.skip(2)
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.buffer_id != other.buffer_id:
            return False
        if self.total_len != other.total_len:
            return False
        if self.reason != other.reason:
            return False
        if self.table_id != other.table_id:
            return False
        if self.cookie != other.cookie:
            return False
        if self.match != other.match:
            return False
        if self.data != other.data:
            return False
        return True

    def pretty_print(self, q):
        q.text("packet_in {")
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
                q.text("buffer_id = ")
                q.text("%#x" % self.buffer_id)
                q.text(",")
                q.breakable()
                q.text("total_len = ")
                q.text("%#x" % self.total_len)
                q.text(",")
                q.breakable()
                q.text("reason = ")
                q.text("%#x" % self.reason)
                q.text(",")
                q.breakable()
                q.text("table_id = ")
                q.text("%#x" % self.table_id)
                q.text(",")
                q.breakable()
                q.text("cookie = ")
                q.text("%#x" % self.cookie)
                q.text(",")
                q.breakable()
                q.text("match = ")
                q.pp(self.match)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


fuzzer.subtypes[10] = packet_in


class packet_out(fuzzer):
    version = 4
    type = 13

    def __init__(self, xid=None, buffer_id=None, in_port=None, actions=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if buffer_id is not None:
            self.buffer_id = buffer_id
        else:
            self.buffer_id = 0
        if in_port is not None:
            self.in_port = in_port
        else:
            self.in_port = 0
        if actions is not None:
            self.actions = actions
        else:
            self.actions = []
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!L", self.buffer_id))
        packed.append(util.pack_port_no(self.in_port))
        packed.append(struct.pack("!H", 0))  # placeholder for actions_len at index 6
        packed.append('\x00' * 6)
        packed.append(loxi.generic_util.pack_list(self.actions))
        packed[6] = struct.pack("!H", len(packed[-1]))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = packet_out()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 13)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.buffer_id = reader.read("!L")[0]
        obj.in_port = util.unpack_port_no(reader)
        _actions_len = reader.read("!H")[0]
        reader.skip(6)
        obj.actions = loxi.generic_util.unpack_list(reader.slice(_actions_len), ofp.action.action.unpack)
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.buffer_id != other.buffer_id:
            return False
        if self.in_port != other.in_port:
            return False
        if self.actions != other.actions:
            return False
        if self.data != other.data:
            return False
        return True

    def pretty_print(self, q):
        q.text("packet_out {")
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
                q.text("buffer_id = ")
                q.text("%#x" % self.buffer_id)
                q.text(",")
                q.breakable()
                q.text("in_port = ")
                q.text(util.pretty_port(self.in_port))
                q.text(",")
                q.breakable()
                q.text("actions = ")
                q.pp(self.actions)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


fuzzer.subtypes[13] = packet_out


class port_desc_stats_request(stats_request):
    version = 4
    type = 18
    stats_type = 13

    def __init__(self, xid=None, flags=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = port_desc_stats_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _stats_type = reader.read("!H")[0]
        assert (_stats_type == 13)
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.flags != other.flags: return False
        return True

    def pretty_print(self, q):
        q.text("port_desc_stats_request {")
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


stats_request.subtypes[13] = port_desc_stats_request


class port_mod(fuzzer):
    version = 4
    type = 16

    def __init__(self, xid=None, port_no=None, hw_addr=None, config=None, mask=None, advertise=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if port_no is not None:
            self.port_no = port_no
        else:
            self.port_no = 0
        if hw_addr is not None:
            self.hw_addr = hw_addr
        else:
            self.hw_addr = [0, 0, 0, 0, 0, 0]
        if config is not None:
            self.config = config
        else:
            self.config = 0
        if mask is not None:
            self.mask = mask
        else:
            self.mask = 0
        if advertise is not None:
            self.advertise = advertise
        else:
            self.advertise = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(util.pack_port_no(self.port_no))
        packed.append('\x00' * 4)
        packed.append(struct.pack("!6B", *self.hw_addr))
        packed.append('\x00' * 2)
        packed.append(struct.pack("!L", self.config))
        packed.append(struct.pack("!L", self.mask))
        packed.append(struct.pack("!L", self.advertise))
        packed.append('\x00' * 4)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = port_mod()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 16)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.port_no = util.unpack_port_no(reader)
        reader.skip(4)
        obj.hw_addr = list(reader.read('!6B'))
        reader.skip(2)
        obj.config = reader.read("!L")[0]
        obj.mask = reader.read("!L")[0]
        obj.advertise = reader.read("!L")[0]
        reader.skip(4)
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.port_no != other.port_no:
            return False
        if self.hw_addr != other.hw_addr:
            return False
        if self.config != other.config:
            return False
        if self.mask != other.mask:
            return False
        if self.advertise != other.advertise:
            return False
        return True

    def pretty_print(self, q):
        q.text("port_mod {")
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
                q.text("port_no = ")
                q.text(util.pretty_port(self.port_no))
                q.text(",")
                q.breakable()
                q.text("hw_addr = ")
                q.text(util.pretty_mac(self.hw_addr))
                q.text(",")
                q.breakable()
                q.text("config = ")
                q.text("%#x" % self.config)
                q.text(",")
                q.breakable()
                q.text("mask = ")
                q.text("%#x" % self.mask)
                q.text(",")
                q.breakable()
                q.text("advertise = ")
                q.text("%#x" % self.advertise)
            q.breakable()
        q.text('}')


fuzzer.subtypes[16] = port_mod


class port_mod_failed_error_msg(error_msg):
    version = 4
    type = 1
    err_type = 7

    def __init__(self, xid=None, code=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if code is not None:
            self.code = code
        else:
            self.code = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        packed.append(struct.pack("!H", self.code))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = port_mod_failed_error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _err_type = reader.read("!H")[0]
        assert (_err_type == 7)
        obj.code = reader.read("!H")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.code != other.code: return False
        if self.data != other.data: return False
        return True

    def pretty_print(self, q):
        q.text("port_mod_failed_error_msg {")
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
                q.text("code = ")
                q.text("%#x" % self.code)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


error_msg.subtypes[7] = port_mod_failed_error_msg


class port_stats_request(stats_request):
    version = 4
    type = 18
    stats_type = 4

    def __init__(self, xid=None, flags=None, port_no=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if port_no is not None:
            self.port_no = port_no
        else:
            self.port_no = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        packed.append(util.pack_port_no(self.port_no))
        packed.append('\x00' * 4)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = port_stats_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _stats_type = reader.read("!H")[0]
        assert (_stats_type == 4)
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        obj.port_no = util.unpack_port_no(reader)
        reader.skip(4)
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.flags != other.flags: return False
        if self.port_no != other.port_no: return False
        return True

    def pretty_print(self, q):
        q.text("port_stats_request {")
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
                q.text(",")
                q.breakable()
                q.text("port_no = ")
                q.text(util.pretty_port(self.port_no))
            q.breakable()
        q.text('}')


stats_request.subtypes[4] = port_stats_request


class port_status(fuzzer):
    version = 4
    type = 12

    def __init__(self, xid=None, reason=None, desc=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if reason is not None:
            self.reason = reason
        else:
            self.reason = 0
        if desc is not None:
            self.desc = desc
        else:
            self.desc = ofp.port_desc()
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!B", self.reason))
        packed.append('\x00' * 7)
        packed.append(self.desc.pack())
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = port_status()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 12)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.reason = reader.read("!B")[0]
        reader.skip(7)
        obj.desc = ofp.port_desc.unpack(reader)
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.reason != other.reason: return False
        if self.desc != other.desc: return False
        return True

    def pretty_print(self, q):
        q.text("port_status {")
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
                q.text("reason = ")
                q.text("%#x" % self.reason)
                q.text(",")
                q.breakable()
                q.text("desc = ")
                q.pp(self.desc)
            q.breakable()
        q.text('}')


fuzzer.subtypes[12] = port_status


class queue_get_config_request(fuzzer):
    version = 4
    type = 22

    def __init__(self, xid=None, port=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if port is not None:
            self.port = port
        else:
            self.port = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(util.pack_port_no(self.port))
        packed.append('\x00' * 4)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = queue_get_config_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 22)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.port = util.unpack_port_no(reader)
        reader.skip(4)
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.port != other.port:
            return False
        return True

    def pretty_print(self, q):
        q.text("queue_get_config_request {")
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
                q.text("port = ")
                q.text(util.pretty_port(self.port))
            q.breakable()
        q.text('}')


fuzzer.subtypes[22] = queue_get_config_request


class queue_op_failed_error_msg(error_msg):
    version = 4
    type = 1
    err_type = 9

    def __init__(self, xid=None, code=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if code is not None:
            self.code = code
        else:
            self.code = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        packed.append(struct.pack("!H", self.code))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = queue_op_failed_error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _err_type = reader.read("!H")[0]
        assert (_err_type == 9)
        obj.code = reader.read("!H")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.code != other.code: return False
        if self.data != other.data: return False
        return True

    def pretty_print(self, q):
        q.text("queue_op_failed_error_msg {")
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
                q.text("code = ")
                q.text("%#x" % self.code)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


error_msg.subtypes[9] = queue_op_failed_error_msg


class queue_stats_request(stats_request):
    version = 4
    type = 18
    stats_type = 5

    def __init__(self, xid=None, flags=None, port_no=None, queue_id=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if port_no is not None:
            self.port_no = port_no
        else:
            self.port_no = 0
        if queue_id is not None:
            self.queue_id = queue_id
        else:
            self.queue_id = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        packed.append(util.pack_port_no(self.port_no))
        packed.append(struct.pack("!L", self.queue_id))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = queue_stats_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _stats_type = reader.read("!H")[0]
        assert (_stats_type == 5)
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        obj.port_no = util.unpack_port_no(reader)
        obj.queue_id = reader.read("!L")[0]
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.flags != other.flags: return False
        if self.port_no != other.port_no: return False
        if self.queue_id != other.queue_id: return False
        return True

    def pretty_print(self, q):
        q.text("queue_stats_request {")
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
                q.text(",")
                q.breakable()
                q.text("port_no = ")
                q.text(util.pretty_port(self.port_no))
                q.text(",")
                q.breakable()
                q.text("queue_id = ")
                q.text("%#x" % self.queue_id)
            q.breakable()
        q.text('}')


stats_request.subtypes[5] = queue_stats_request


class role_request(fuzzer):
    version = 4
    type = 24

    def __init__(self, xid=None, role=None, generation_id=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if role is not None:
            self.role = role
        else:
            self.role = 0
        if generation_id is not None:
            self.generation_id = generation_id
        else:
            self.generation_id = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!L", self.role))
        packed.append('\x00' * 4)
        packed.append(struct.pack("!Q", self.generation_id))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = role_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 24)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.role = reader.read("!L")[0]
        reader.skip(4)
        obj.generation_id = reader.read("!Q")[0]
        return obj

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.xid != other.xid:
            return False
        if self.role != other.role:
            return False
        if self.generation_id != other.generation_id:
            return False
        return True

    def pretty_print(self, q):
        q.text("role_request {")
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
                q.text("role = ")
                q.text("%#x" % self.role)
                q.text(",")
                q.breakable()
                q.text("generation_id = ")
                q.text("%#x" % self.generation_id)
            q.breakable()
        q.text('}')


fuzzer.subtypes[24] = role_request


class role_request_failed_error_msg(error_msg):
    version = 4
    type = 1
    err_type = 11

    def __init__(self, xid=None, code=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if code is not None:
            self.code = code
        else:
            self.code = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        packed.append(struct.pack("!H", self.code))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = role_request_failed_error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _err_type = reader.read("!H")[0]
        assert (_err_type == 11)
        obj.code = reader.read("!H")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.code != other.code: return False
        if self.data != other.data: return False
        return True

    def pretty_print(self, q):
        q.text("role_request_failed_error_msg {")
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
                q.text("code = ")
                q.text("%#x" % self.code)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


error_msg.subtypes[11] = role_request_failed_error_msg


class set_config(fuzzer):
    version = 4
    type = 9

    def __init__(self, xid=None, flags=None, miss_send_len=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if miss_send_len is not None:
            self.miss_send_len = miss_send_len
        else:
            self.miss_send_len = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.flags))
        packed.append(struct.pack("!H", self.miss_send_len))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = set_config()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 9)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.flags = reader.read("!H")[0]
        obj.miss_send_len = reader.read("!H")[0]
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.flags != other.flags: return False
        if self.miss_send_len != other.miss_send_len: return False
        return True

    def pretty_print(self, q):
        q.text("set_config {")
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
                q.text(",")
                q.breakable()
                q.text("miss_send_len = ")
                q.text("%#x" % self.miss_send_len)
            q.breakable()
        q.text('}')


fuzzer.subtypes[9] = set_config


class switch_config_failed_error_msg(error_msg):
    version = 4
    type = 1
    err_type = 10

    def __init__(self, xid=None, code=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if code is not None:
            self.code = code
        else:
            self.code = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        packed.append(struct.pack("!H", self.code))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = switch_config_failed_error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _err_type = reader.read("!H")[0]
        assert (_err_type == 10)
        obj.code = reader.read("!H")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.code != other.code: return False
        if self.data != other.data: return False
        return True

    def pretty_print(self, q):
        q.text("switch_config_failed_error_msg {")
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
                q.text("code = ")
                q.text("%#x" % self.code)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


error_msg.subtypes[10] = switch_config_failed_error_msg


class table_features_failed_error_msg(error_msg):
    version = 4
    type = 1
    err_type = 13

    def __init__(self, xid=None, code=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if code is not None:
            self.code = code
        else:
            self.code = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        packed.append(struct.pack("!H", self.code))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = table_features_failed_error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _err_type = reader.read("!H")[0]
        assert (_err_type == 13)
        obj.code = reader.read("!H")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.code != other.code: return False
        if self.data != other.data: return False
        return True

    def pretty_print(self, q):
        q.text("table_features_failed_error_msg {")
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
                q.text("code = ")
                q.text("%#x" % self.code)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


error_msg.subtypes[13] = table_features_failed_error_msg


class table_features_stats_request(stats_request):
    version = 4
    type = 18
    stats_type = 12

    def __init__(self, xid=None, flags=None, entries=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        if entries is not None:
            self.entries = entries
        else:
            self.entries = []
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        packed.append(loxi.generic_util.pack_list(self.entries))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = table_features_stats_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _stats_type = reader.read("!H")[0]
        assert (_stats_type == 12)
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        obj.entries = loxi.generic_util.unpack_list(reader, ofp.common.table_features.unpack)
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.flags != other.flags: return False
        if self.entries != other.entries: return False
        return True

    def pretty_print(self, q):
        q.text("table_features_stats_request {")
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
                q.text(",")
                q.breakable()
                q.text("entries = ")
                q.pp(self.entries)
            q.breakable()
        q.text('}')


stats_request.subtypes[12] = table_features_stats_request


class table_mod(fuzzer):
    version = 4
    type = 17

    def __init__(self, xid=None, table_id=None, config=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if table_id is not None:
            self.table_id = table_id
        else:
            self.table_id = 0
        if config is not None:
            self.config = config
        else:
            self.config = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!B", self.table_id))
        packed.append('\x00' * 3)
        packed.append(struct.pack("!L", self.config))
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = table_mod()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 17)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        obj.table_id = reader.read("!B")[0]
        reader.skip(3)
        obj.config = reader.read("!L")[0]
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.table_id != other.table_id: return False
        if self.config != other.config: return False
        return True

    def pretty_print(self, q):
        q.text("table_mod {")
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
                q.text("table_id = ")
                q.text("%#x" % self.table_id)
                q.text(",")
                q.breakable()
                q.text("config = ")
                q.text("%#x" % self.config)
            q.breakable()
        q.text('}')


fuzzer.subtypes[17] = table_mod


class table_mod_failed_error_msg(error_msg):
    version = 4
    type = 1
    err_type = 8

    def __init__(self, xid=None, code=None, data=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if code is not None:
            self.code = code
        else:
            self.code = 0
        if data is not None:
            self.data = data
        else:
            self.data = ''
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.err_type))
        packed.append(struct.pack("!H", self.code))
        packed.append(self.data)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = table_mod_failed_error_msg()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 1)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _err_type = reader.read("!H")[0]
        assert (_err_type == 8)
        obj.code = reader.read("!H")[0]
        obj.data = str(reader.read_all())
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.code != other.code: return False
        if self.data != other.data: return False
        return True

    def pretty_print(self, q):
        q.text("table_mod_failed_error_msg {")
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
                q.text("code = ")
                q.text("%#x" % self.code)
                q.text(",")
                q.breakable()
                q.text("data = ")
                q.pp(self.data)
            q.breakable()
        q.text('}')


error_msg.subtypes[8] = table_mod_failed_error_msg


class table_stats_request(stats_request):
    version = 4
    type = 18
    stats_type = 3

    def __init__(self, xid=None, flags=None):
        if xid is not None:
            self.xid = xid
        else:
            self.xid = None
        if flags is not None:
            self.flags = flags
        else:
            self.flags = 0
        return

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.version))
        packed.append(struct.pack("!B", self.type))
        packed.append(struct.pack("!H", 0))  # placeholder for length at index 2
        packed.append(struct.pack("!L", self.xid))
        packed.append(struct.pack("!H", self.stats_type))
        packed.append(struct.pack("!H", self.flags))
        packed.append('\x00' * 4)
        length = sum([len(x) for x in packed])
        packed[2] = struct.pack("!H", length)
        return ''.join(packed)

    @staticmethod
    def unpack(reader):
        obj = table_stats_request()
        _version = reader.read("!B")[0]
        assert (_version == 4)
        _type = reader.read("!B")[0]
        assert (_type == 18)
        _length = reader.read("!H")[0]
        orig_reader = reader
        reader = orig_reader.slice(_length, 4)
        obj.xid = reader.read("!L")[0]
        _stats_type = reader.read("!H")[0]
        assert (_stats_type == 3)
        obj.flags = reader.read("!H")[0]
        reader.skip(4)
        return obj

    def __eq__(self, other):
        if type(self) != type(other): return False
        if self.xid != other.xid: return False
        if self.flags != other.flags: return False
        return True

    def pretty_print(self, q):
        q.text("table_stats_request {")
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


stats_request.subtypes[3] = table_stats_request


def parse_header(buf):
    if len(buf) < 8:
        raise loxi.ProtocolError("too short to be an OpenFlow message")
    return struct.unpack_from("!BBHL", buf)


def parse_message(buf):
    msg_ver, msg_type, msg_len, msg_xid = parse_header(buf)
    if msg_ver != ofp.OFP_VERSION and msg_type != ofp.OFPT_HELLO:
        raise loxi.ProtocolError("wrong OpenFlow version (expected %d, got %d)" % (ofp.OFP_VERSION, msg_ver))
    if len(buf) != msg_len:
        raise loxi.ProtocolError("incorrect message size")
    return fuzzer.unpack(loxi.generic_util.OFReader(buf))
