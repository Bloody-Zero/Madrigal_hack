"""Deterministic first-observed TCP reassembly with gaps and conflict masks."""
from collections import defaultdict
from .common import LabError, check_cancel

MAX_SPAN = 16 * 1024 * 1024
MAX_TOTAL_SPAN = 128 * 1024 * 1024


def ranges(mask, target=1):
    result, start = [], None
    for i, value in enumerate(mask):
        if value == target and start is None:
            start = i
        elif value != target and start is not None:
            result.append([start, i]); start = None
    if start is not None:
        result.append([start, len(mask)])
    return result


def signed_delta(seq, base):
    return ((seq - base + 2**31) % 2**32) - 2**31


def reassemble(capture, source_id, cancel=None):
    groups = defaultdict(list)
    for p in capture['packets']:
        groups[p['stream']].append(p)
    if len(groups) > 1000:
        raise LabError('Предел MVP: 1000 соединений в источнике.')
    output = []
    total = 0
    for session, packets in groups.items():
        check_cancel(cancel)
        opening = next((p for p in packets if p['flags'] & 2 and not p['flags'] & 16), None)
        first = opening or packets[0]
        a, b = (first['src'], first['sport']), (first['dst'], first['dport'])
        for direction, endpoint in enumerate((a, b)):
            pp = [p for p in packets if (p['src'], p['sport']) == endpoint]
            syn = next((p for p in pp if p['flags'] & 2), None)
            data = [p for p in pp if p['expected_length']]
            anchor = ((syn['seq'] + 1) % 2**32) if syn else ((data[0]['seq'] + bool(data[0]['flags'] & 2)) % 2**32 if data else 0)
            positions = [(signed_delta((p['seq'] + bool(p['flags'] & 2)) % 2**32, anchor), p) for p in data]
            low = min([0] + [x for x, _ in positions])
            fin_positions = [signed_delta((p['seq']+bool(p['flags'] & 2)) % 2**32,anchor)+p['expected_length']
                             for p in pp if p['flags'] & 1]
            high = max([0] + [x + p['expected_length'] for x, p in positions] + fin_positions)
            span = high-low
            total += span
            sid = f'{source_id}:{session}:{direction}'
            base = (anchor + low) % 2**32
            meta = {'id': sid, 'source_id': source_id, 'session': session, 'direction': direction,
                    'from': list(endpoint), 'to': list(b if direction == 0 else a),
                    'roles_known': opening is not None, 'start_seen': syn is not None,
                    'base_seq': base, 'length': span, 'packet_count': len(pp),
                    'policy': 'first-observed; конфликтные байты не интерпретируются',
                    'error': None}
            if span > MAX_SPAN or total > MAX_TOTAL_SPAN:
                meta.update(error='Защитный предел диапазона потока превышен; поток не обрезан.', hex='', known='', conflicts='', provenance=[], gaps=[], conflict_ranges=[])
                output.append(meta)
                continue
            buf, known, conflicts = bytearray(span), bytearray(span), bytearray(span)
            provenance = []
            for idx, (pos, p) in enumerate(positions):
                if idx % 100 == 0:
                    check_cancel(cancel)
                start = pos-low
                payload = bytes.fromhex(p['payload'])
                provenance.append({'frame': p['frame'], 'start': start, 'end': start+len(payload),
                                   'expected_end': start+p['expected_length'], 'packet_offset': p['payload_offset'],
                                   'time': p['time']})
                end = start+len(payload)
                if 1 not in known[start:end]:
                    buf[start:end] = payload
                    known[start:end] = b'\1' * len(payload)
                else:
                    for j, value in enumerate(payload, start):
                        if known[j] and buf[j] != value:
                            conflicts[j] = 1
                        elif not known[j]:
                            buf[j] = value; known[j] = 1
            meta.update(hex=buf.hex(), known=known.hex(), conflicts=conflicts.hex(),
                        provenance=provenance, gaps=ranges(known, 0), conflict_ranges=ranges(conflicts))
            output.append(meta)
    return output


def references(stream, start, end):
    return [{'frame': p['frame'], 'packet_start': p['packet_offset'] + max(start, p['start'])-p['start'],
             'packet_end': p['packet_offset'] + min(end, p['end'])-p['start'],
             'stream_start': max(start, p['start']), 'stream_end': min(end, p['end']), 'time': p['time']}
            for p in stream['provenance'] if p['start'] < end and p['end'] > start]
