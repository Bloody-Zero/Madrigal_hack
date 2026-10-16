"""Reproducible small benchmark. Peak RSS is process-lifetime, not tracemalloc."""
import argparse
import json
import resource
import tempfile
import time
from pathlib import Path
from lab.project import Project
from tools.make_examples import packet, message, handshake, write_pcap


def main():
    p=argparse.ArgumentParser();p.add_argument('--sessions',type=int,default=20)
    p.add_argument('--messages',type=int,default=50);p.add_argument('--body-size',type=int,default=128)
    args=p.parse_args()
    frames=[]
    for s in range(args.sessions):
        # Change ISNs and explicitly close between sessions on the same four tuple.
        isn=1000+s*100000
        frames.extend(handshake(isn));seq=isn+1
        for _ in range(args.messages):
            payload=message(body=b'Z'*args.body_size,command=2)
            frames.append(packet(seq,payload));seq+=len(payload)
        frames.append(packet(seq,flags=4))
    with tempfile.TemporaryDirectory() as root:
        source=Path(root)/'load.pcap';write_pcap(source,frames)
        del frames
        project=Project(Path(root)/'project')
        start=time.perf_counter();project.import_capture(source.name,source.read_bytes());import_seconds=time.perf_counter()-start
        chosen=[s['id'] for s in project.streams() if s['length']]
        result=project.run(chosen)
        print(json.dumps({'source_bytes':source.stat().st_size,'packets':project.data['sources'][0]['packet_count'],
            'sessions':len(chosen),'messages':sum(result['counts'].values()),'counts':result['counts'],
            'import_seconds':import_seconds,'check_seconds':result['seconds'],
            'parent_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            'max_child_peak_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            'note':'Linux measurements; not a certification of the full 100 MiB / 250k packet target'},indent=2))


if __name__=='__main__':main()
