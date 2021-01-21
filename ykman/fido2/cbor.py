# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


"""
Minimal CBOR implementation supporting a subset of functionality and types
required for FIDO 2 CTAP.
"""

import struct
import six


def dump_int(data, mt=0):
    if data < 0:
        mt = 1
        data = -1 - data

    mt = mt << 5
    if data <= 23:
        args = (">B", mt | data)
    elif data <= 0xFF:
        args = (">BB", mt | 24, data)
    elif data <= 0xFFFF:
        args = (">BH", mt | 25, data)
    elif data <= 0xFFFFFFFF:
        args = (">BI", mt | 26, data)
    else:
        args = (">BQ", mt | 27, data)
    return struct.pack(*args)


def dump_bool(data):
    return b"\xf5" if data else b"\xf4"


def dump_list(data):
    return dump_int(len(data), mt=4) + b"".join([encode(x) for x in data])


def _sort_keys(entry):
    key = entry[0]
    return six.indexbytes(key, 0), len(key), key


def dump_dict(data):
    items = [(encode(k), encode(v)) for k, v in data.items()]
    items.sort(key=_sort_keys)
    return dump_int(len(items), mt=5) + b"".join([k + v for (k, v) in items])


def dump_bytes(data):
    return dump_int(len(data), mt=2) + data


def dump_text(data):
    data_bytes = data.encode("utf8")
    return dump_int(len(data_bytes), mt=3) + data_bytes


_SERIALIZERS = [
    (bool, dump_bool),
    (six.integer_types, dump_int),
    (dict, dump_dict),
    (list, dump_list),
    (six.text_type, dump_text),
    (six.binary_type, dump_bytes),
]


def encode(data):
    for k, v in _SERIALIZERS:
        if isinstance(data, k):
            return v(data)
    raise ValueError("Unsupported value: {}".format(data))


def load_int(ai, data):
    if ai < 24:
        return ai, data
    elif ai == 24:
        return six.indexbytes(data, 0), data[1:]
    elif ai == 25:
        return struct.unpack_from(">H", data)[0], data[2:]
    elif ai == 26:
        return struct.unpack_from(">I", data)[0], data[4:]
    elif ai == 27:
        return struct.unpack_from(">Q", data)[0], data[8:]
    raise ValueError("Invalid additional information")


def load_nint(ai, data):
    val, rest = load_int(ai, data)
    return -1 - val, rest


def load_bool(ai, data):
    return ai == 21, data


def load_bytes(ai, data):
    l, data = load_int(ai, data)
    return data[:l], data[l:]


def load_text(ai, data):
    enc, rest = load_bytes(ai, data)
    return enc.decode("utf8"), rest


def load_array(ai, data):
    l, data = load_int(ai, data)
    values = []
    for i in range(l):
        val, data = decode_from(data)
        values.append(val)
    return values, data


def load_map(ai, data):
    l, data = load_int(ai, data)
    values = {}
    for i in range(l):
        k, data = decode_from(data)
        v, data = decode_from(data)
        values[k] = v
    return values, data


_DESERIALIZERS = {
    0: load_int,
    1: load_nint,
    2: load_bytes,
    3: load_text,
    4: load_array,
    5: load_map,
    7: load_bool,
}


def decode_from(data):
    fb = six.indexbytes(data, 0)
    return _DESERIALIZERS[fb >> 5](fb & 0b11111, data[1:])


def decode(data):
    value, rest = decode_from(data)
    if rest != b"":
        raise ValueError("Extraneous data")
    return value
