import copy
import json
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from lab.capture import read_capture
from lab.common import LabError, Cancelled, digest
from lab.project import Project
from lab.rules import DEFAULT, parse_stream, validate
from lab.streams import reassemble, references
from lab.app import create_app
from tools.make_examples import generate


class LaboratoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.examples=generate(Path(cls.tmp.name)/'examples')
        cls.expected=json.loads((cls.examples/'expected.json').read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def stream(self,name):
        c=read_capture(self.examples/name)
        return reassemble(c,digest((self.examples/name).read_bytes()))[0]

    def test_pcap_and_pcapng_identical(self):
        for name in ('training.pcap','training.pcapng'):
            s=self.stream(name)
            self.assertEqual(s['hex'],self.expected['training_stream_hex'])
            self.assertEqual(parse_stream(s,DEFAULT)['counts'],{'ok':3})

    def test_reordering_and_retransmission(self):
        s=self.stream('reordered_repeated.pcap')
        self.assertEqual(s['hex'],self.expected['training_stream_hex'])
        self.assertEqual(len(s['provenance']),4)

    def test_gap_is_not_zero_value(self):
        s=self.stream('gap.pcap')
        self.assertTrue(s['gaps'])
        result=parse_stream(s,DEFAULT)
        self.assertIn('incomplete',result['counts'])
        self.assertTrue(all(not row['fields'] for row in result['rows']))

    def test_conflict_is_not_interpreted(self):
        s=self.stream('conflict.pcap')
        self.assertTrue(s['conflict_ranges'])
        r=parse_stream(s,DEFAULT)
        self.assertIn('ambiguous',r['counts'])
        self.assertFalse(r['rows'][0]['fields'])

    def test_truncation_is_explicit(self):
        s=self.stream('truncated.pcap')
        self.assertEqual(s['gaps'],[[6,7]])
        self.assertEqual(parse_stream(s,DEFAULT)['counts'],{'incomplete':1})

    def test_sequence_wraparound(self):
        s=self.stream('wraparound.pcap')
        self.assertFalse(s['gaps'])
        self.assertEqual(s['hex'],'aa550100020015')

    def test_reused_four_tuple_separate_sessions(self):
        c=read_capture(self.examples/'reused.pcap')
        streams=reassemble(c,'source')
        self.assertEqual(len({s['session'] for s in streams}),2)
        self.assertEqual([s['hex'] for s in streams if s['length']][-1],'aa550100020063')

    def test_missing_start_roles_unknown(self):
        s=self.stream('midstream.pcap')
        self.assertFalse(s['roles_known']);self.assertFalse(s['start_seen'])

    def test_provenance_recovers_exact_source_bytes(self):
        c=read_capture(self.examples/'training.pcap')
        s=reassemble(c,'source')[0]
        refs=references(s,2,10)
        rebuilt=bytearray()
        for r in refs:
            packet=next(p for p in c['packets'] if p['frame']==r['frame'])
            rebuilt.extend(bytes.fromhex(packet['raw'])[r['packet_start']:r['packet_end']])
        self.assertEqual(bytes(rebuilt),bytes.fromhex(s['hex'])[2:10])

    def test_variable_size_and_new_values(self):
        rule=copy.deepcopy(DEFAULT)
        rule['fields'].append({'name':'value','offset':5,'type':'uint16','endian':'big'})
        r=parse_stream(self.stream('additional.pcap'),rule)
        self.assertEqual(r['counts'],{'ok':2})
        self.assertEqual(r['rows'][0]['fields'][-1]['value'],300)
        self.assertEqual(r['rows'][1]['end']-r['rows'][1]['start'],265)

    def test_bad_rule_counterexample_then_correction(self):
        s=self.stream('additional.pcap')
        wrong=copy.deepcopy(DEFAULT);wrong['framing']['width']=1
        self.assertIn('violation',parse_stream(s,wrong)['counts'])
        self.assertEqual(parse_stream(s,DEFAULT)['counts'],{'ok':2})

    def test_unknown_areas_remain_visible(self):
        rule={'framing':{'mode':'fixed','size':7},'fields':[{'name':'command','type':'uint8','offset':2}]}
        row=parse_stream(self.stream('wraparound.pcap'),rule)['rows'][0]
        self.assertEqual(row['unknown_ranges'],[[0,2],[3,7]])

    def test_invalid_rules_rejected(self):
        for change in ({'mode':'fixed','size':0},{'mode':'length','width':3,'offset':0}):
            rule=copy.deepcopy(DEFAULT);rule['framing']=change
            with self.assertRaises(LabError):validate(rule)

    def test_cancelled_import_does_not_publish(self):
        with tempfile.TemporaryDirectory() as root:
            p=Project(root);event=threading.Event();event.set()
            with self.assertRaises(Cancelled):
                p.import_capture('test.pcap',(self.examples/'training.pcap').read_bytes(),event)
            self.assertEqual(p.data['sources'],[])

    def test_project_dedup_staleness_and_move(self):
        with tempfile.TemporaryDirectory() as root:
            p=Project(Path(root)/'before')
            raw=(self.examples/'training.pcap').read_bytes()
            p.import_capture('training.pcap',raw)
            self.assertTrue(p.import_capture('again.pcap',raw)['duplicate'])
            ids=[s['id'] for s in p.streams() if s['length']]
            run=p.run(ids)
            p.add_note({'stream_id':ids[0],'start':5,'end':7,'text':'Гипотеза о параметре'})
            rule=copy.deepcopy(DEFAULT);rule['name']='Изменённое описание';p.set_rule(rule)
            self.assertTrue(p.summary()['runs'][0]['stale'])
            p.set_rule(DEFAULT)
            shutil.copytree(Path(root)/'before',Path(root)/'after')
            shutil.rmtree(Path(root)/'before')
            moved=Project(Path(root)/'after')
            repeated=moved.run(ids)
            self.assertEqual(run['counts'],repeated['counts'])
            self.assertEqual(len(moved.data['notes']),1)
            self.assertIn('Гипотеза',moved.report(repeated['id']))

    def test_changed_source_detected(self):
        with tempfile.TemporaryDirectory() as root:
            p=Project(root);p.import_capture('test.pcap',(self.examples/'training.pcap').read_bytes())
            p.path_for(p.data['sources'][0]['path']).write_bytes(b'changed')
            with self.assertRaises(LabError):p.run([p.streams()[0]['id']])

    def test_checksum_warning_does_not_drop_packet(self):
        c=read_capture(self.examples/'bad_checksum.pcap')
        self.assertTrue(c['packets'])
        self.assertEqual(c['packets'][-1]['checksum'],'0')

    def test_api_local_mutation_token(self):
        with tempfile.TemporaryDirectory() as root,TestClient(create_app(root)) as c:
            self.assertEqual(c.get('/').status_code,200)
            self.assertEqual(c.post('/api/rule',json=DEFAULT).status_code,403)
            token=c.get('/api/bootstrap').json()['token']
            self.assertEqual(c.post('/api/rule',json=DEFAULT,headers={'X-Lab-Token':token}).status_code,200)
            self.assertEqual(c.get('/api/project',headers={'Host':'evil.example'}).status_code,403)

    def test_exclusive_project_lock(self):
        with tempfile.TemporaryDirectory() as root:
            first,second=Project(root),Project(root)
            first.acquire()
            try:
                with self.assertRaises(LabError):second.acquire()
            finally:first.release()
            second.acquire();second.release()

    def test_empty_variable_body(self):
        from tools.make_examples import handshake,packet,message,write_pcap
        f=self.examples/'empty.pcap'
        write_pcap(f,handshake()+[packet(1001,message(body=b'',command=2))])
        self.assertEqual(parse_stream(self.stream('empty.pcap'),DEFAULT)['counts'],{'ok':1})

    def test_missing_tail_inferred_from_fin(self):
        from tools.make_examples import handshake,packet,write_pcap
        f=self.examples/'missing-tail.pcap'
        write_pcap(f,handshake()+[packet(1001,b'ABC'),packet(1007,flags=0x11)])
        self.assertEqual(self.stream('missing-tail.pcap')['gaps'],[[3,6]])


if __name__=='__main__':unittest.main()
