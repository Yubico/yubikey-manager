import struct
import six


def ser_int(data, mt=0):
    if data < 0:
        mt = 1
        data = -1 - data

    mt = mt << 5
    if data <= 23:
        args = ('>B', mt | data)
    elif data <= 0xff:
        args = ('>BB', mt | 24, data)
    elif data <= 0xffff:
        args = ('>BH', mt | 25, data)
    elif data <= 0xffffffff:
        args = ('>BI', mt | 26, data)
    else:
        args = ('>BQ', mt | 27, data)
    return struct.pack(*args)


def ser_bool(data):
    return b'\xf5' if data else b'\xf4'


def ser_list(data):
    return ser_int(len(data), mt=4) + b''.join([serialize(x) for x in data])


def _sort_keys(x):
    return (six.indexbytes(x, 0), len(x), x)


def ser_dict(data):
    items = [(serialize(k), serialize(v)) for k, v in data.items()]
    items.sort(key=_sort_keys)
    return ser_int(len(items), mt=5) + b''.join([k+v for (k, v) in items])


def ser_bytes(data):
    return ser_int(len(data), mt=2) + data


def ser_text(data):
    data = data.encode('utf8')
    return ser_int(len(data), mt=3) + data


_SERIALIZERS = {
    int: ser_int,
    bool: ser_bool,
    dict: ser_dict,
    list: ser_list,
    six.text_type: ser_text,
    six.binary_type: ser_bytes
}


def serialize(data):
    for k, v in _SERIALIZERS.items():
        if isinstance(data, k):
            return v(data)
    raise ValueError('Unsupported value: {}'.format(data))


def des_int(ai, data):
    if ai < 24:
        return ai, data
    elif ai == 24:
        return six.indexbytes(data, 0), data[1:]
    elif ai == 25:
        return struct.unpack_from('>H', data)[0], data[2:]
    elif ai == 26:
        return struct.unpack_from('>I', data)[0], data[4:]
    elif ai == 27:
        return struct.unpack_from('>Q', data)[0], data[8:]
    raise ValueError('Invalid additional information')


def des_nint(ai, data):
    val, rest = des_int(ai, data)
    return -1 - val, rest


def des_bool(ai, data):
    return ai == 21, data


def des_bytes(ai, data):
    l, data = des_int(ai, data)
    return data[:l], data[l:]


def des_text(ai, data):
    enc, rest = des_bytes(ai, data)
    return enc.decode('utf8'), rest


def des_array(ai, data):
    l, data = des_int(ai, data)
    values = []
    for i in range(l):
        val, data = deserialize(data)
        values.append(val)
    return values, data


def des_map(ai, data):
    l, data = des_int(ai, data)
    values = {}
    for i in range(l):
        k, data = deserialize(data)
        v, data = deserialize(data)
        values[k] = v
    return values, data


_DESERIALIZERS = {
    0: des_int,
    1: des_nint,
    2: des_bytes,
    3: des_text,
    4: des_array,
    5: des_map,
    7: des_bool
}


def deserialize(data):
    fb = six.indexbytes(data, 0)
    return _DESERIALIZERS[fb >> 5](fb & 0b11111, data[1:])
