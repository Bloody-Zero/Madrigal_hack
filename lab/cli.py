import argparse
import json
import sys
from pathlib import Path
from .common import LabError, read_json
from .project import Project


def main():
    parser=argparse.ArgumentParser(description='Лаборатория протоколов: тот же движок без интерфейса')
    sub=parser.add_subparsers(dest='command',required=True)
    check=sub.add_parser('check'); check.add_argument('--project',required=True)
    check.add_argument('--capture'); check.add_argument('--rule')
    check.add_argument('--stream',action='append',help='Точный ID потока; повторяемый параметр')
    check.add_argument('--direction',type=int,choices=[0,1],help='Ограничить направление; 0 = от первой стороны')
    args=parser.parse_args()
    try:
        p=Project(args.project)
        p.acquire()
        if args.rule:
            candidate=Path(args.rule)
            if not candidate.exists():
                candidate=p.path_for(args.rule)
            p.set_rule(read_json(candidate))
        imported=None
        if args.capture:
            f=Path(args.capture)
            imported=p.import_capture(f.name,f.read_bytes())['source_id']
        ids=args.stream or [s['id'] for s in p.streams() if (not imported or s['source_id']==imported)
            and (args.direction is None or s['direction']==args.direction)]
        run=p.run(ids)
        print(json.dumps(run,ensure_ascii=False,indent=2))
        return 0 if set(run['counts']).issubset({'ok','not_applicable'}) else 2
    except (LabError,OSError,ValueError) as e:
        print(str(e),file=sys.stderr)
        return 1
    finally:
        if 'p' in locals():
            p.release()


if __name__=='__main__':
    sys.exit(main())
