"""Small declarative parser; no eval, scripts, plugins or implicit byte guessing."""
import struct
from collections import Counter
from .common import LabError, check_cancel, digest
from .streams import ranges

MAX_MESSAGES = 100_000
MAX_MESSAGE_SIZE = 1024 * 1024
TYPES = {'uint8': 1, 'uint16': 2, 'uint32': 4, 'int8': 1, 'int16': 2, 'int32': 4, 'float32': 4}
DEFAULT = {'name': 'Учебный: AA55 + тип + длина тела', 'framing': {'mode': 'length',
    'offset': 3, 'width': 2, 'endian': 'big', 'add': 5, 'min_size': 5, 'max_size': 65541},
    'fields': [{'name': 'marker', 'offset': 0, 'type': 'bytes', 'size': 2, 'equals': 'aa55'},
               {'name': 'command', 'offset': 2, 'type': 'uint8'},
               {'name': 'body_length', 'offset': 3, 'type': 'uint16', 'endian': 'big'},
               {'name': 'body', 'offset': 5, 'type': 'bytes', 'size': 'rest'}]}
PROFILES = {'length': DEFAULT,
    'fixed': {'name': 'Фиксированные сообщения, пример 7 байт', 'framing': {'mode': 'fixed', 'size': 7},
              'fields': [{'name': 'raw', 'offset': 0, 'type': 'bytes', 'size': 'rest'}]},
    'marker_length': {**DEFAULT, 'name': 'Маркер AA55 + длина (настроить под запись)'}}


def integer(value, label, lo=0, hi=MAX_MESSAGE_SIZE):
    if type(value) is not int or not lo <= value <= hi:
        raise LabError(f'{label}: ожидается целое число от {lo} до {hi}')
    return value


def validate(rule):
    if not isinstance(rule, dict) or not isinstance(rule.get('framing'), dict):
        raise LabError('Нужен JSON-объект с framing и fields')
    f = rule['framing']
    if f.get('mode') == 'fixed':
        integer(f.get('size'), 'framing.size', 1)
    elif f.get('mode') == 'length':
        integer(f.get('offset'), 'framing.offset')
        if f.get('width') not in (1, 2, 4):
            raise LabError('Ширина поля длины: 1, 2 или 4')
        integer(f.get('add', 0), 'framing.add', -MAX_MESSAGE_SIZE)
        integer(f.get('min_size', 1), 'framing.min_size', 1)
        integer(f.get('max_size', MAX_MESSAGE_SIZE), 'framing.max_size', 1)
        if f.get('max_size', MAX_MESSAGE_SIZE) < f.get('min_size', 1):
            raise LabError('max_size меньше min_size')
        if f.get('endian', 'big') not in ('big', 'little'):
            raise LabError('endian: big или little')
    else:
        raise LabError('framing.mode: fixed или length')
    integer(rule.get('start_offset', 0), 'start_offset')
    fields = rule.get('fields')
    if not isinstance(fields, list) or not 1 <= len(fields) <= 128:
        raise LabError('fields: от 1 до 128 полей')
    names = set()
    for field in fields:
        if not isinstance(field, dict) or not isinstance(field.get('name'), str) or not field['name']:
            raise LabError('Каждому полю нужно имя')
        if field['name'] in names:
            raise LabError('Имена полей должны быть уникальны')
        names.add(field['name'])
        integer(field.get('offset'), 'field.offset')
        typ = field.get('type')
        if typ not in TYPES and typ not in ('bytes', 'utf8'):
            raise LabError('Неизвестный тип поля: ' + str(typ))
        if typ in ('bytes', 'utf8') and field.get('size') != 'rest':
            integer(field.get('size'), 'field.size', 1)
        if field.get('endian', 'big') not in ('big', 'little'):
            raise LabError('endian: big или little')
        for key in ('min', 'max'):
            if key in field and (type(field[key]) not in (int, float) or typ not in TYPES):
                raise LabError(f'{key} допустим только для числового поля')
    return rule


def parse_stream(stream, rule, cancel=None):
    validate(rule)
    rows, counts = [], Counter()
    base = {'stream_id': stream['id'], 'source_id': stream['source_id'], 'rule_hash': digest(rule)}
    if stream['error']:
        return {'rows': [{**base, 'start': 0, 'end': stream['length'], 'status': 'uncovered',
                          'errors': [stream['error']], 'fields': [],
                          'unknown_ranges': [[0,stream['length']]]}], 'counts': {'uncovered': 1}}
    data = bytes.fromhex(stream['hex'])
    known = bytes.fromhex(stream['known'])
    conflict = bytes.fromhex(stream['conflicts'])
    n, at = len(data), rule.get('start_offset', 0)

    def append(start, end, status, errors, fields=None, unknown=None):
        counts[status] += 1
        rows.append({**base, 'start': start, 'end': end, 'status': status, 'errors': errors,
                     'fields': fields or [], 'unknown_ranges': unknown or []})

    if at:
        append(0, min(at, n), 'uncovered', ['До start_offset'], unknown=[[0, min(at, n)]])
    framing = rule['framing']
    while at < n:
        if len(rows) >= MAX_MESSAGES:
            raise LabError('Более 100 000 результатов на поток; проверка не опубликована.')
        check_cancel(cancel)
        if framing['mode'] == 'fixed':
            size = framing['size']
        else:
            a, b = at+framing['offset'], at+framing['offset']+framing['width']
            if b > n or 0 in known[a:b] or 1 in conflict[a:b]:
                status = 'ambiguous' if 1 in conflict[a:min(b, n)] else 'incomplete'
                append(at, n, status, ['Поле длины недоступно; остаток не разбирается'], unknown=[[at, n]])
                break
            size = int.from_bytes(data[a:b], framing.get('endian', 'big'))+framing.get('add', 0)
            if not max(1, framing.get('min_size', 1), b-at) <= size <= framing.get('max_size', MAX_MESSAGE_SIZE):
                append(at, n, 'violation', [f'Недопустимая длина {size}; остаток не разбирается'], unknown=[[at, n]])
                break
        end = min(at+size, n)
        if at+size > n or 0 in known[at:end]:
            append(at, end, 'incomplete', ['Сообщение неполно; значения не извлечены'], unknown=[[at, end]])
            at = end
            continue
        if 1 in conflict[at:end]:
            append(at, end, 'ambiguous', ['Конфликтующие перекрытия; значения не извлечены'], unknown=[[at, end]])
            at = end
            continue
        values, errors, covered = [], [], bytearray(size)
        for f in rule['fields']:
            off, typ = f['offset'], f['type']
            length = TYPES[typ] if typ in TYPES else (size-off if f['size'] == 'rest' else f['size'])
            if off > size or length < 0 or off+length > size:
                errors.append(f"{f['name']}: выход за границы сообщения")
                continue
            raw = data[at+off:at+off+length]
            covered[off:off+length] = b'\1'*length
            try:
                if typ.startswith(('uint', 'int')):
                    value = int.from_bytes(raw, f.get('endian', 'big'), signed=typ.startswith('int'))
                elif typ == 'float32':
                    value = struct.unpack(('>' if f.get('endian', 'big') == 'big' else '<')+'f', raw)[0]
                    import math
                    if not math.isfinite(value):
                        raise ValueError('не конечное число')
                else:
                    value = raw.hex() if typ == 'bytes' else raw.decode('utf-8')
                if 'equals' in f and value != f['equals']:
                    errors.append(f"{f['name']}: {value!r} != {f['equals']!r}")
                if 'min' in f and value < f['min'] or 'max' in f and value > f['max']:
                    errors.append(f"{f['name']}: вне допустимого диапазона")
                values.append({'name': f['name'], 'value': value, 'type': typ,
                               'start': at+off, 'end': at+off+length})
            except (ValueError, UnicodeError) as e:
                errors.append(f"{f['name']}: {e}")
        unknown = [[at+a, at+b] for a, b in ranges(covered, 0)]
        append(at, end, 'violation' if errors else 'ok', errors, values, unknown)
        at = end
    if not n:
        append(0, 0, 'not_applicable', ['Нет прикладных байтов'])
    return {'rows': rows, 'counts': dict(counts)}
