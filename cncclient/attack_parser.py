#!/usr/bin/env python3

from construct import *

ATK_VECS = [
    "UDP",
    "VSE",
    "DNS",
    "SYN",
    "ACK",
    "STOMP",
    "GREIP",
    "GREETH",
    "PROXY",
    "UDP_PLAIN",
    "HTTP",
]

ATK_OPTS = [
    "PAYLOAD_SIZE",
    "PAYLOAD_RAND",
    "IP_TOS",
    "IP_IDENT",
    "IP_TTL",
    "IP_DF",
    "SPORT",
    "DPORT",
    "DOMAIN",
    "DNS_HDR_ID",
    "TCPCC",
    "URG",
    "ACK",
    "PSH",
    "RST",
    "SYN",
    "FIN",
    "SEQRND",
    "ACKRND",
    "GRE_CONSTIP",
    "METHOD",
    "POST_DATA",
    "PATH",
    "HTTPS",
    "CONNS",
    "SOURCE",
]

# Converts Construct objects to native python objects (list, dict)
def construct_pythonize(obj):
    if isinstance(obj, Container):
        return {k: construct_jsonify(v) for k, v in obj.items() if not k.startswith('_')}
    elif isinstance(obj, ListContainer):
        return [construct_jsonify(v) for v in obj]
    else:
        return obj

# b"\x7f\x00\x00\x01" <-> "127.0.0.1"
IpAddress = ExprAdapter(Byte[4],
    encoder = lambda obj,ctx: list(map(int, obj.split("."))),
    decoder = lambda obj,ctx: "{0}.{1}.{2}.{3}".format(*obj),
)

# b"\x7f\x00\x00\x01\x18" <-> "127.0.0.1/24"
IpAddressNetmask = ExprAdapter(IpAddress >> Int8ub,
    encoder = lambda obj,ctx: ListContainer(obj.split('/')[0], int(obj.split('/')[1])),
    decoder = lambda obj,ctx: '{}/{}'.format(*obj),
)

# [{"key": "foo", "value": "bar"}, {"key": "a", "value": "b"}] <-> {"foo": "bar", "a": "b"}
class MappingAdapter(Adapter):
    key_name = 'key'
    value_name = 'value'
    def _encode(self, obj, context):
        return ListContainer(Container({self.key_name: key, self.value_name: value}) for key, value in obj.items())
    def _decode(self, obj, context):
        return Container({x[self.key_name]: x[self.value_name] for x in obj})

Attack = Struct(
    "duration" / Int32ub,
    "attack_type" / Enum(Int8ub,
        **dict(map(reversed, enumerate(ATK_VECS)))
    ),
    "_target_count" / Int8ub,
    "targets" / Array(this._target_count,
        IpAddressNetmask
    ),
    "_options_count" / Int8ub,
    "options" / MappingAdapter(
        Array(this._options_count,
            Struct(
                "key" / Enum(Int8ub,
                    **dict(map(reversed, enumerate(ATK_OPTS)))
                ),
                "_value_len" / Int8ub,
                "value" / String(this._value_len,
                    encoding='ascii',
                ),
            ),
        ),
    ),
)

def parse_atk(s):
    return construct_pythonize(Attack.parse(s))

if __name__ == "__main__":
    # Example commands received
    attacks = {
        ("sdrfafasyy.top", 23): [
            b'\x00\x00\x00x\n\x01h\x1f\x01\xad \x02\x18\x0245\x08\x11mostwantedhf.info',
        ],
        ("fuck1.bagthebook.com", 23): [
            b'\x00\x00\x00\x0f\x03\x01$\xf8\x0c@ \x00',
            b'\x00\x00\x00\x0f\x04\x01$\xf8\x0c@ \x00',
            b'\x00\x00\x00\x0f\t\x01$\xf8\x0c@ \x00',
            b'\x00\x00\x00\x0f\x03\x01$\xf8\x0c@ \x00',
            b'\x00\x00\x00\x0f\x04\x01$\xf8\x0c@ \x00',
            b'\x00\x00\x00\x1e\x04\x01y(\xb5\xf0 \x00',
            b'\x00\x00\x00\x1e\t\x01y(\xb5\xf0 \x00',
        ],
        ("www.mufoscam.org", 23) : [
            b'\x00\x00\x00x\x00\x01m\xa3\xe0" \x03\x07\x0280\x00\x041024\x06\x0280',
            b'\x00\x00\x00x\x00\x01m\xa3\xe0" \x03\x06\x0280\x07\x0280\x00\x0510240',
            b'\x00\x00\x00\xf0\x00\x01m\xa3\xe0" \x03\x00\x0532000\x06\x0280\x07\x0280',
            b'\x00\x00\x00x\x06\x01)9Q\x00\x18\x01\x00\x041024',
            b'\x00\x00\x02X\x06\x01)9Q\x00\x18\x00',
            b'\x00\x00\x0e\x10\x04\x01)9Q\x00\x18\x03\x06\x0280\x00\x041024\r\x011',
            b'\x00\x00\x00x\x04\x01)9Q\x00\x1a\x00',
            b'\x00\x00\x00x\x04\x01)9Q\x1e \x01\x00\x013'
        ]
    }

    for host, port in attacks:
        print(host + ':' + str(port))
        for s in attacks[host, port]:
            atk = parse_atk(s)
            print('', atk)


