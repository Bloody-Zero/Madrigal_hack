"""Shared errors, canonical hashing and atomic persistence."""
import hashlib
import json
import os
import tempfile
from pathlib import Path


class LabError(ValueError):
    pass


class Cancelled(LabError):
    pass


def digest(value):
    data = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(value, f, ensure_ascii=False, indent=2, allow_nan=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def check_cancel(event):
    if event is not None and event.is_set():
        raise Cancelled('Задача отменена; предыдущие результаты сохранены.')
