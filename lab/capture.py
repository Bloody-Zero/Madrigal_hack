"""TShark adapter. Read-only, no live capture and no shell invocation."""
import json
import os
import shutil
import struct
import subprocess
import tempfile
import threading
from pathlib import Path
from .common import LabError, check_cancel

MAX_CAPTURE = 100 * 1024 * 1024
MAX_PACKETS = 250_000
FIELDS = ['frame.number', 'frame.time_epoch', 'frame.len', 'frame.cap_len',
          'frame.encap_type', 'frame.interface_id', 'ip.src', 'ip.dst',
          'ip.flags.mf', 'ip.frag_offset', 'tcp.stream', 'tcp.srcport',
          'tcp.dstport', 'tcp.seq_raw', 'tcp.ack_raw', 'tcp.flags',
          'tcp.len', 'tcp.payload', 'tcp.checksum.status', '@frame']


def flatten(obj, out):
    for key, value in obj.items():
        if isinstance(value, dict):
            flatten(value, out)
        elif key in out and isinstance(value, str):
            out[key] = value


def json_objects(pipe):
    decoder = json.JSONDecoder()
    buffer, eof = '', False
    while True:
        buffer = buffer.lstrip(' \t\r\n[,')
        if buffer.startswith(']'):
            if buffer[1:].strip():
                raise LabError('Лишние данные после JSON TShark')
            return
        if buffer:
            try:
                item, end = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                if eof:
                    raise LabError('Неполный вывод TShark')
            else:
                yield item
                buffer = buffer[end:]
                continue
        if eof:
            raise LabError('Нет завершённого массива TShark')
        chunk = pipe.read(65536)
        if not chunk:
            eof = True
        buffer += chunk
        if len(buffer) > 8 * 1024 * 1024:
            raise LabError('Превышен предел представления одного пакета TShark')


def executable():
    value = os.environ.get('TSHARK') or shutil.which('tshark')
    if not value:
        raise LabError('TShark не найден. Установите tshark или задайте переменную TSHARK.')
    return value


def version():
    return subprocess.check_output([executable(), '--version'], text=True, stderr=subprocess.DEVNULL).splitlines()[0]


def payload_offset(raw):
    """Validate our declared Ethernet/IPv4/no-fragment scope, locate TCP bytes."""
    if len(raw) < 14:
        raise LabError('Усечённый Ethernet-заголовок')
    typ = int.from_bytes(raw[12:14], 'big')
    off = 14
    while typ in (0x8100, 0x88a8):
        if len(raw) < off + 4:
            raise LabError('Усечённый VLAN-заголовок')
        typ = int.from_bytes(raw[off+2:off+4], 'big')
        off += 4
    if typ != 0x0800:
        return None  # Background ARP/IPv6/etc is not interpreted as IPv4.
    if len(raw) < off + 20 or raw[off] >> 4 != 4:
        raise LabError('Усечённый или некорректный IPv4-заголовок')
    ihl = (raw[off] & 15) * 4
    if ihl < 20 or len(raw) < off + ihl:
        raise LabError('Недостаточно данных IPv4-заголовка')
    if raw[off+9] != 6:
        return None
    if int.from_bytes(raw[off+6:off+8], 'big') & 0x3fff:
        raise LabError('IP-фрагментация не поддерживается в MVP')
    tcp = off + ihl
    if len(raw) < tcp + 20:
        raise LabError('Усечённый TCP-заголовок')
    thl = (raw[tcp+12] >> 4) * 4
    if thl < 20 or len(raw) < tcp + thl:
        raise LabError('Некорректная длина TCP-заголовка')
    total = int.from_bytes(raw[off+2:off+4], 'big')
    expected = total - ihl - thl
    if expected < 0:
        raise LabError('Некорректная длина IPv4/TCP')
    return tcp + thl, expected


def read_capture(path, cancel=None, progress=None):
    check_cancel(cancel)
    path = Path(path)
    if path.stat().st_size > MAX_CAPTURE:
        raise LabError('Предел источника: 100 МиБ. Файл не обрезан и не импортирован.')
    cmd = [executable(), '-n', '-r', str(path), '-o', 'tcp.relative_sequence_numbers:FALSE',
           '-o', 'tcp.check_checksum:TRUE', '-o', 'tcp.desegment_tcp_streams:FALSE',
           '-T', 'json', '-x', '-J', 'frame eth ip tcp']
    packets, diagnostics = [], []
    interfaces = set()
    with tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err, text=True, encoding='utf-8')
        finished = threading.Event()

        def monitor():
            while not finished.wait(.1):
                if cancel is not None and cancel.is_set():
                    proc.terminate()
                    return

        threading.Thread(target=monitor, daemon=True).start()
        try:
            for count, item in enumerate(json_objects(proc.stdout), 1):
                check_cancel(cancel)
                if count > MAX_PACKETS:
                    raise LabError('Предел 250 000 пакетов превышен; импорт не опубликован.')
                layers = item['_source']['layers']
                d = {key: '' for key in FIELDS}
                flatten(layers, d)
                d['@frame'] = layers['frame_raw'][0]
                frame = int(d['frame.number'])
                interfaces.add(d['frame.interface_id'] or '0')
                if len(interfaces) > 1:
                    raise LabError('MVP принимает записи только с одного интерфейса.')
                raw = bytes.fromhex(d['@frame'].replace(':', ''))
                if d['frame.encap_type'] != '1':
                    diagnostics.append({'frame': frame, 'kind': 'unsupported', 'text': 'Поддерживается Ethernet; этот пакет не разобран.'})
                    continue
                try:
                    located = payload_offset(raw)
                except LabError as e:
                    diagnostics.append({'frame': frame, 'kind': 'invalid', 'text': str(e)})
                    continue
                if located is None:
                    diagnostics.append({'frame': frame, 'kind': 'background', 'text': 'Фоновый трафик вне TCP/IPv4.'})
                    continue
                if not d['tcp.stream']:
                    diagnostics.append({'frame': frame, 'kind': 'invalid', 'text': 'TShark не выделил TCP-соединение.'})
                    continue
                offset, expected = located
                payload = raw[offset:offset+expected]
                packets.append({'frame': frame, 'time': d['frame.time_epoch'],
                    'wire_length': int(d['frame.len']), 'captured_length': len(raw),
                    'stream': d['tcp.stream'], 'src': d['ip.src'], 'dst': d['ip.dst'],
                    'sport': int(d['tcp.srcport']), 'dport': int(d['tcp.dstport']),
                    'seq': int(d['tcp.seq_raw']), 'ack': int(d['tcp.ack_raw']),
                    'flags': int(d['tcp.flags'], 16), 'expected_length': expected,
                    'payload': payload.hex(), 'payload_offset': offset,
                    'raw': raw.hex(), 'checksum': d['tcp.checksum.status']})
                if progress and count % 200 == 0:
                    progress(count, 'Чтение пакетов')
            proc.wait()
            check_cancel(cancel)
            err.seek(0)
            message = err.read().decode(errors='replace')[-4000:]
            if proc.returncode:
                raise LabError('TShark: ' + message)
        except LabError:
            check_cancel(cancel)
            raise
        finally:
            finished.set()
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            proc.stdout.close()
    return {'packets': packets, 'diagnostics': diagnostics, 'packet_count': count if 'count' in locals() else 0,
            'tshark_version': version(), 'checksum_policy': 'Проверять и предупреждать; не отбрасывать автоматически. Возможен offloading.'}
