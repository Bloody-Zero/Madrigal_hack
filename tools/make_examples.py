"""Synthetic Ethernet captures with independently specified expected values.
These are generated packet fixtures, NOT recordings of a physical device.
"""
import json
import socket
import struct
from pathlib import Path


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!'+'H'*(len(data)//2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(seq, payload=b'', flags=0x18, reverse=False, ack=9001, sport=53024):
    src, dst = socket.inet_aton('192.0.2.10'), socket.inet_aton('192.0.2.20')
    sp, dp = sport, 9000
    if reverse:
        src, dst, sp, dp = dst, src, dp, sp
    tcp = struct.pack('!HHIIBBHHH', sp, dp, seq % 2**32, ack % 2**32, 0x50, flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack('!BBH', 0, 6, len(tcp)+len(payload))
    c = checksum(pseudo+tcp+payload)
    tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40+len(payload), 1, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10]+struct.pack('!H', checksum(ip))+ip[12:]
    return bytes.fromhex('0200000000020200000000010800')+ip+tcp+payload


def message(value=None, body=None, command=1):
    body = value.to_bytes(2, 'big') if body is None else body
    return b'\xaa\x55'+bytes([command])+len(body).to_bytes(2, 'big')+body


def handshake(seq=1000):
    return [packet(seq, flags=2, ack=0), packet(9000, flags=0x12, reverse=True, ack=seq+1),
            packet(seq+1, flags=0x10)]


def write_pcap(path, frames):
    with Path(path).open('wb') as f:
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, item in enumerate(frames):
            raw, wire = item if isinstance(item, tuple) else (item, len(item))
            f.write(struct.pack('<IIII', 1700000000, i*1000 % 1000000, len(raw), wire))
            f.write(raw)


def block(typ, body):
    body += b'\0'*(-len(body) % 4)
    return struct.pack('<II', typ, len(body)+12)+body+struct.pack('<I', len(body)+12)


def write_pcapng(path, frames):
    data = block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    data += block(1, struct.pack('<HHI', 1, 0, 65535))
    for i, raw in enumerate(frames):
        stamp = 1700000000 * 1000000+i*1000
        data += block(6, struct.pack('<IIIII', 0, stamp >> 32, stamp & 0xffffffff, len(raw), len(raw))+raw)
    Path(path).write_bytes(data)


def generate(directory):
    directory = Path(directory); directory.mkdir(parents=True, exist_ok=True)
    body = message(21)+message(35)+message(body=b'ABCDEF', command=2)
    frames = handshake()+[packet(1001, body[:4]), packet(1005, body[4:12]), packet(1013, body[12:])]
    write_pcap(directory/'training.pcap', frames)
    write_pcapng(directory/'training.pcapng', frames)
    new = message(300)+message(body=b'Z'*260, command=2)
    write_pcap(directory/'additional.pcap', handshake()+[packet(1001, new)])
    write_pcap(directory/'reordered_repeated.pcap', handshake()+[frames[5], frames[3], frames[4], frames[4]])
    write_pcap(directory/'gap.pcap', handshake()+[frames[3], frames[5]])
    write_pcap(directory/'conflict.pcap', frames+[packet(1006, b'\xff')])
    last = packet(1001, message(21))
    write_pcap(directory/'truncated.pcap', handshake()+[(last[:-1],len(last))])
    write_pcap(directory/'midstream.pcap', [packet(1001, body)])
    write_pcap(directory/'reused.pcap', frames+[packet(1001+len(body), flags=4)]+handshake(2000)+[packet(2001, message(99))])
    wrap = message(21)
    write_pcap(directory/'wraparound.pcap', handshake(0xfffffffc)+[packet(0xfffffffd, wrap[:4]), packet(1, wrap[4:])])
    bad = bytearray(frames[3]); bad[50] ^= 255
    write_pcap(directory/'bad_checksum.pcap', handshake()+[bytes(bad)])
    (directory/'actions.csv').write_text('source,time,action,value\ntraining.pcap,1700000000.003,set,21\ntraining.pcap,1700000000.004,set,35\ntraining.pcap,1700000000.005,read_array,6\nadditional.pcap,1700000000.003,set,300\n', encoding='utf-8')
    (directory/'expected.json').write_text(json.dumps({'training_stream_hex':body.hex(), 'training_values':[21,35],
        'additional_value':300,'additional_array_length':260,'fixture_kind':'synthetic Ethernet packet fixtures'},indent=2))
    return directory


if __name__ == '__main__':
    import sys
    generate(sys.argv[1] if len(sys.argv)>1 else Path(__file__).resolve().parents[1]/'examples')
