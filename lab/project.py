"""Portable project store and common GUI/CLI research operations."""
import copy
import csv
import html
import io
import os
import tempfile
import threading
import time
import uuid
import zipfile
from collections import Counter
from pathlib import Path
from . import __version__
from .common import LabError, check_cancel, digest, read_json, write_json
from .capture import read_capture, MAX_CAPTURE
from .streams import reassemble, references
from .rules import DEFAULT, validate, parse_stream


class Project:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.path = self.root/'project.json'
        if not self.path.exists():
            write_json(self.path, {'schema': 1, 'name': self.root.name, 'sources': [],
                'rule': copy.deepcopy(DEFAULT), 'notes': [], 'actions': [], 'runs': []})
        self.data = read_json(self.path)
        if self.data.get('schema') != 1:
            raise LabError('Неизвестная версия проекта')
        validate(self.data['rule'])
        self._cache = {}
        self._lockfile = None

    def acquire(self):
        """One app or CLI writer per project, including across processes."""
        self._lockfile = (self.root/'.lab.lock').open('a+b')
        try:
            if os.name == 'nt':
                import msvcrt
                self._lockfile.seek(0); self._lockfile.write(b'0'); self._lockfile.flush(); self._lockfile.seek(0)
                msvcrt.locking(self._lockfile.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(self._lockfile,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            self._lockfile.close(); self._lockfile=None
            raise LabError('Проект уже открыт другим процессом. Закройте его перед запуском CLI или второго приложения.')
        self.data=read_json(self.path)

    def release(self):
        if self._lockfile is not None:
            self._lockfile.close(); self._lockfile=None

    def save(self):
        write_json(self.path, self.data)

    def path_for(self, relative):
        target = (self.root/relative).resolve()
        if not target.is_relative_to(self.root):
            raise LabError('Путь выходит за пределы проекта')
        return target

    def source(self, source_id):
        return next((s for s in self.data['sources'] if s['id'] == source_id), None)

    def source_data(self, source_id):
        if not self.source(source_id):
            raise LabError('Источник не найден')
        if source_id not in self._cache:
            self._cache[source_id] = read_json(self.path_for(f'cache/{source_id}.json'))
        return self._cache[source_id]

    def verify(self, source_ids):
        for sid in source_ids:
            src = self.source(sid)
            if not src or digest(self.path_for(src['path']).read_bytes()) != src['sha256']:
                raise LabError('Исходный файл отсутствует или изменён: ' + str(sid))

    def import_capture(self, name, raw, cancel=None, progress=None):
        if len(raw) > MAX_CAPTURE:
            raise LabError('Предел файла: 100 МиБ')
        if Path(name).suffix.lower() not in ('.pcap', '.pcapng'):
            raise LabError('Выберите файл .pcap или .pcapng')
        sid = digest(raw)
        with self.lock:
            if self.source(sid):
                return {'source_id': sid, 'duplicate': True}
        target = self.path_for('sources/'+sid+Path(name).suffix.lower())
        target.parent.mkdir(exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=target.parent)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(raw)
            start = time.perf_counter()
            capture = read_capture(tmp, cancel, progress)
            streams = reassemble(capture, sid, cancel)
            check_cancel(cancel)
            elapsed = time.perf_counter()-start
            cache = {'capture': capture, 'streams': streams, 'engine_version': __version__}
            meta = {'id': sid, 'name': Path(name).name, 'path': str(target.relative_to(self.root)),
                    'sha256': sid, 'size': len(raw), 'packet_count': capture['packet_count'],
                    'import_seconds': elapsed, 'tshark_version': capture['tshark_version'],
                    'diagnostic_count': len(capture['diagnostics'])}
            with self.lock:
                check_cancel(cancel)
                os.replace(tmp, target)
                write_json(self.path_for(f'cache/{sid}.json'), cache)
                self.data['sources'].append(meta)
                self.save()
                self._cache[sid] = cache
            return {'source_id': sid, 'duplicate': False}
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def streams(self):
        return [s for source in self.data['sources'] for s in self.source_data(source['id'])['streams']]

    def stream(self, stream_id):
        source = stream_id.split(':')[0]
        return next((s for s in self.source_data(source)['streams'] if s['id'] == stream_id), None)

    def summary(self):
        with self.lock:
            d = copy.deepcopy(self.data)
        for run in d['runs']:
            run['stale'] = run['rule_hash'] != digest(d['rule']) or run.get('engine_version') != __version__
        d['streams'] = [{k: v for k, v in s.items() if k not in ('hex', 'known', 'conflicts', 'provenance')}
                        for s in self.streams()]
        d['project_path'] = str(self.root)
        d['version'] = __version__
        return d

    def set_rule(self, rule):
        validate(rule)
        with self.lock:
            self.data['rule'] = copy.deepcopy(rule)
            write_json(self.path_for('interpretations/'+digest(rule)+'.json'), rule)
            self.save()

    def run(self, stream_ids, cancel=None, progress=None):
        with self.lock:
            rule = copy.deepcopy(self.data['rule'])
        chosen = list(dict.fromkeys(stream_ids))
        if not chosen:
            raise LabError('Выберите хотя бы один поток')
        self.verify({sid.split(':')[0] for sid in chosen})
        start = time.perf_counter()
        rows, counts, diagnostics = [], Counter(), []
        for i, sid in enumerate(chosen):
            check_cancel(cancel)
            stream = self.stream(sid)
            if stream is None:
                raise LabError('Поток не найден: '+sid)
            result = parse_stream(stream, rule, cancel)
            rows.extend(result['rows']); counts.update(result['counts'])
            diagnostics.append({'stream_id':sid, 'start_seen':stream['start_seen'], 'roles_known':stream['roles_known'],
                                'gaps':stream['gaps'], 'conflict_ranges':stream['conflict_ranges'], 'error':stream['error']})
            if len(rows) > 100_000:
                raise LabError('Предел проверки: 100 000 результатов. Проверка не опубликована.')
            if progress:
                progress(i+1, f'Проверка потоков {i+1}/{len(chosen)}')
        meta = {'id': uuid.uuid4().hex, 'created': time.time(), 'rule_hash': digest(rule),
                'source_hashes': sorted({sid.split(':')[0] for sid in chosen}), 'stream_ids': chosen,
                'counts': dict(counts), 'seconds':time.perf_counter()-start, 'engine_version':__version__,
                'unknown_bytes':sum(b-a for row in rows for a,b in row['unknown_ranges']),
                'settings':{'overlap':'first-observed; conflicts not interpreted', 'checksum':'warn, do not drop',
                            'time':'packet observation timestamps; action clock offset is explicit'}}
        result = {**meta, 'rule':rule, 'rows':rows, 'stream_diagnostics':diagnostics}
        with self.lock:
            check_cancel(cancel)
            write_json(self.path_for('runs/'+meta['id']+'.json'), result)
            self.data['runs'].insert(0, meta)
            self.save()
        return meta

    def run_data(self, run_id):
        if not any(r['id'] == run_id for r in self.data['runs']):
            raise LabError('Проверка не найдена')
        return read_json(self.path_for('runs/'+run_id+'.json'))

    def add_note(self, note):
        kind = note.get('kind', 'hypothesis')
        if kind not in ('observation', 'hypothesis', 'conclusion', 'question'):
            raise LabError('Неизвестный вид записи')
        if not isinstance(note.get('text'), str) or not note['text'].strip():
            raise LabError('Введите текст наблюдения')
        s = self.stream(note.get('stream_id', ''))
        if not s:
            raise LabError('Выберите поток')
        start, end = note.get('start'), note.get('end')
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= s['length']:
            raise LabError('Диапазон: 0 <= начало < конец <= длина потока')
        value = {'id':uuid.uuid4().hex, 'kind':kind, 'text':note['text'][:10000], 'stream_id':s['id'],
                 'source_id':s['source_id'], 'start':start, 'end':end, 'base_seq':s['base_seq'],
                 'evidence':references(s,start,end), 'created':time.time()}
        with self.lock:
            self.data['notes'].append(value); self.save()
        return value

    def import_actions(self, text, clock_offset=0):
        import math
        clock_offset = float(clock_offset)
        if not math.isfinite(clock_offset):
            raise LabError('Смещение часов должно быть конечным числом')
        reader = csv.DictReader(io.StringIO(text))
        if not {'source','time','action'}.issubset(set(reader.fieldnames or [])):
            raise LabError('CSV: обязательные столбцы source,time,action; необязательный value')
        result = []
        for row in reader:
            matches = [s for s in self.data['sources'] if s['name'] == row['source'] or s['id'] == row['source']]
            if len(matches) != 1:
                raise LabError('Источник действия не найден или неоднозначен: '+row['source'])
            stamp = float(row['time'])
            if not math.isfinite(stamp):
                raise LabError('Время должно быть конечным Unix timestamp')
            result.append({'id':uuid.uuid4().hex, 'source_id':matches[0]['id'], 'original_time':stamp,
                           'clock_offset':clock_offset, 'capture_time':stamp+clock_offset,
                           'action':row['action'], 'value':row.get('value','')})
            if len(result)>100_000:
                raise LabError('Слишком много действий')
        with self.lock:
            self.data['actions'].extend(result); self.save()
        return len(result)

    def report(self, run_id):
        run = self.run_data(run_id)
        e = lambda v: html.escape(str(v))
        stale = run['rule_hash'] != digest(self.data['rule']) or run['engine_version'] != __version__
        out = ['<!doctype html><meta charset="utf-8"><title>Отчёт исследования</title>',
            '<style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:20px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px}pre{white-space:pre-wrap}</style>',
            '<h1>Исследование бинарного обмена</h1>', '<p>Результат: '+('УСТАРЕЛ' if stale else 'актуален относительно текущих правил')+'</p>',
            '<p>Успешный разбор не доказывает смысл полей и универсальность описания.</p>',
            '<h2>Корпус и настройки</h2><pre>'+e({k:run[k] for k in ('source_hashes','stream_ids','rule_hash','settings','counts','unknown_bytes','seconds')})+'</pre>',
            '<h2>Правила</h2><pre>'+e(__import__('json').dumps(run['rule'],ensure_ascii=False,indent=2))+'</pre>',
            '<h2>Источники</h2><pre>'+e(self.data['sources'])+'</pre>',
            '<h2>Журнал действий</h2><pre>'+e(self.data['actions'])+'</pre>',
            '<h2>Наблюдения, основания и открытые вопросы</h2>']
        for note in self.data['notes']:
            out.append('<p>'+e(note)+'</p>')
        out += ['<h2>Диагностика потоков</h2><pre>'+e(run['stream_diagnostics'])+'</pre>',
                '<h2>Все результаты и контрпримеры</h2><table><tr><th>Поток / диапазон</th><th>Статус</th><th>Значения</th><th>Ошибки / неизвестные области</th></tr>']
        for row in run['rows']:
            out.append('<tr><td>'+e(row['stream_id'])+'<br>'+e([row['start'],row['end']])+'</td><td>'+e(row['status'])+'</td><td>'+e({f['name']:f['value'] for f in row['fields']})+'</td><td>'+e(row['errors'])+' '+e(row['unknown_ranges'])+'</td></tr>')
        out += ['</table><h2>Повторное применение</h2><pre>python -m lab.cli check --project PATH --capture NEW.pcap --rule interpretations/RULE_HASH.json</pre>']
        result = ''.join(out)
        path = self.path_for('reports/'+run_id+'.html'); path.parent.mkdir(exist_ok=True)
        path.write_text(result,encoding='utf-8')
        return result

    def export(self):
        self.verify([s['id'] for s in self.data['sources']])
        out = io.BytesIO()
        with self.lock, zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
            for path in sorted(self.root.rglob('*')):
                if path.is_symlink() or not path.is_file() or path.name == '.lab.lock':
                    continue
                if not path.resolve().is_relative_to(self.root):
                    raise LabError('Внешняя ссылка внутри проекта')
                z.write(path,str(path.relative_to(self.root)))
        return out.getvalue()
