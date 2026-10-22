import io
import json
from pathlib import Path
import sys
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
import collector
import fingerprint as fp
import test_lab as helpers


class UnusualProvider(BaseHTTPRequestHandler):
    calls = []
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.calls.append(self.path)
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        try:
            if self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location','/normal')
                self.end_headers()
                return
            if self.path == '/headers':
                self.wfile.write(b'HTTP/1.1 200 OK\r\nX-Slow: ')
                for _ in range(100):
                    self.wfile.write(b'x'); self.wfile.flush(); time.sleep(.03)
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.end_headers()
            if self.path == '/large':
                self.wfile.write(b'data: '+b'x'*20000); self.wfile.flush()
                return
            if self.path in ('/drip', '/cancel', '/stall'):
                self.wfile.write(b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n')
                self.wfile.flush()
                if self.path == '/stall':
                    time.sleep(2)
                    return
                for _ in range(100):
                    self.wfile.write(b': ping\n\n'); self.wfile.flush(); time.sleep(.03)
                return
            if self.path == '/events':
                self.wfile.write(b'data: {}\n\n'*20)
                return
            chunks = [dict(model='a', choices=[{'delta':{'content':'你好'}}]),
                      dict(model='b', choices=[{'delta':{},'finish_reason':'stop'}])]
            body = ''.join('data: '+json.dumps(c, ensure_ascii=False)+'\n\n' for c in chunks)
            if self.path != '/truncated':
                body += 'data: [DONE]\n\n'
            # Split inside UTF-8 characters and across SSE event boundaries.
            for byte in body.encode():
                self.wfile.write(bytes([byte])); self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),UnusualProvider)
        cls.server.daemon_threads=True
        threading.Thread(target=cls.server.serve_forever,daemon=True).start()
        cls.base='http://127.0.0.1:'+str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()

    def collect(self, path, timeout=.2, **kw):
        return collector.collect(self.base+path, 'fake-key', {'stream':True}, timeout, **kw)

    def test_continuous_and_stalled_responses_obey_deadline(self):
        for path in ('/drip','/stall','/headers'):
            with self.subTest(path=path):
                before=time.monotonic()
                row,raw=self.collect(path)
                self.assertLess(time.monotonic()-before,1.5)
                self.assertFalse(row['complete'])
                self.assertEqual(row['termination_reason'],'deadline_exceeded')
                if path != '/headers':
                    self.assertIn(b'partial',raw)
                    self.assertEqual(row['text'],'partial')

    def test_cancel_interrupts_and_keeps_partial_evidence(self):
        cancel=threading.Event()
        timer=threading.Timer(.15,cancel.set); timer.start()
        try:
            row,raw=self.collect('/cancel',timeout=5,cancel=cancel)
        finally:
            timer.join()
        self.assertEqual(row['termination_reason'],'cancelled')
        self.assertIn(b'partial',raw)
        self.assertFalse(row['complete'])
        self.assertLess(row['total_s'],1.5)

    def test_oversize_unterminated_line_is_bounded(self):
        row,raw=self.collect('/large',max_bytes=100)
        self.assertEqual(len(raw),100)
        self.assertEqual(row['termination_reason'],'response_size_limit')
        self.assertFalse(row['complete'])

    def test_event_limit(self):
        row,raw=self.collect('/events',max_events=3)
        self.assertEqual(len(row['events']),3)
        self.assertEqual(row['termination_reason'],'event_count_limit')
        self.assertTrue(raw)

    def test_fragmented_unicode_and_midstream_model_change(self):
        row,raw=self.collect('/normal',timeout=2)
        self.assertTrue(row['complete'],row['error'])
        self.assertEqual(row['text'],'你好')
        self.assertEqual(row['model_values'],['a','b'])
        self.assertEqual(fp.agreement([row])['model']['within_response_changes'],1)
        row['case_id']='stream'
        self.assertEqual(fp.summarize([row])['anomalies'][0]['kind'],'metadata')

    def test_missing_done_is_incomplete(self):
        row,_=self.collect('/truncated',timeout=2)
        self.assertFalse(row['complete'])
        self.assertFalse(row['done'])

    def test_redirect_is_not_followed(self):
        UnusualProvider.calls.clear()
        row,_=self.collect('/redirect')
        self.assertEqual(row['http_status'],302)
        self.assertFalse(row['complete'])
        self.assertEqual(UnusualProvider.calls,['/redirect'])

    def test_tls_handshake_can_be_cancelled(self):
        listener=socket.socket()
        listener.bind(('127.0.0.1',0)); listener.listen()
        stop=threading.Event()
        def peer():
            conn,_=listener.accept()
            with conn:
                stop.wait(2)
        worker=threading.Thread(target=peer,daemon=True); worker.start()
        cancel=threading.Event()
        timer=threading.Timer(.2,cancel.set); timer.start()
        try:
            row,_=collector.collect('https://127.0.0.1:'+str(listener.getsockname()[1]),
                                    'fake-key',{},5,cancel=cancel)
            self.assertEqual(row['termination_reason'],'cancelled')
            self.assertLess(row['total_s'],1.5)
        finally:
            stop.set(); listener.close(); timer.join(); worker.join(3)


class SignalReliabilityTests(unittest.TestCase):
    def test_nested_usage_paths(self):
        result=fp.signals([{'case_id':'x','usage':{
            'prompt_tokens_details':{'cached_tokens':2},
            'completion_tokens_details':{'reasoning_tokens':3}}}])['usage_keys']
        self.assertIn('prompt_tokens_details.cached_tokens',result['cached'])
        self.assertIn('completion_tokens_details.reasoning_tokens',result['reasoning'])

    def test_legacy_events_reveal_model_change(self):
        row={'model':'b','events':[{'data':'{"model":"a"}'},{'data':'[DONE]'}]}
        self.assertEqual(fp.agreement([row])['model']['values'],['a','b'])

    def test_only_compare_tokenization_for_identical_outputs(self):
        def row(text,tokens):
            return dict(case_id='logprobs',complete=True,text=text,
                        logprobs={'tokens':len(tokens),'first_tokens':tokens})
        items=fp.logprobs_signals([row('hello',['he','llo']),row('world',['world'])])
        self.assertEqual(len(items),2)
        self.assertTrue(all(i['stable'] is None for i in items))
        items=fp.logprobs_signals([row('hello',['he','llo']),row('hello',['hello'])])
        self.assertEqual(len(items),1)
        self.assertFalse(items[0]['stable'])

    def test_discovery_validation_precedes_all_network_calls(self):
        with tempfile.TemporaryDirectory() as d:
            lab=app.Lab(d)
            for url in ['http://remote.example/v1','https://user:pass@example.com','https://example.com?key=x']:
                with self.subTest(url=url), patch.object(collector,'list_models') as network:
                    with self.assertRaises(ValueError):
                        lab.discover({'base_url':url,'api_key':'fake-key'})
                    network.assert_not_called()
                with patch('urllib.request.build_opener') as network:
                    with self.assertRaises(ValueError):
                        collector.list_models(url,'fake-key',1)
                    network.assert_not_called()

    def test_snapshot_detects_same_count_replacement(self):
        with tempfile.TemporaryDirectory() as d:
            lab=app.Lab(d)
            with patch.object(lab,'references',return_value=[{'source':'local','label':'A'}]):
                original=lab.library_snapshot()
            with patch.object(lab,'references',return_value=[{'source':'local','label':'B'}]):
                changed=lab.library_snapshot(original)
            self.assertIn('检测时为',changed)
            self.assertNotEqual(original,changed)


class ReferenceExportTests(helpers.LabHarness, unittest.TestCase):
    def test_export_contains_replayable_current_and_collected_references(self):
        def run():
            rid=self.server.lab.start(self.config(cases=app.PRESETS['models'],repeats=1))['run_id']
            self.wait_run()
            return rid
        official=run()
        self.server.lab.add_reference({'run_id':official,'label':'reference'})
        entered,release=threading.Event(),threading.Event()
        original_collect=collector.collect
        def gated(*args,**kwargs):
            entered.set()
            release.wait(3)
            return original_collect(*args,**kwargs)
        with patch.object(collector,'collect',side_effect=gated):
            target=self.server.lab.start(self.config(cases=app.PRESETS['models'],repeats=1))['run_id']
            try:
                self.assertTrue(entered.wait(2))
                self.server.lab.delete_reference(self.server.lab.references()[0]['id'])
            finally:
                release.set()
            self.wait_run()
        collected=self.server.lab.load(target)['manifest']['reference_set_sha256']
        with self.request('/api/export?id='+target) as response:
            archive=zipfile.ZipFile(io.BytesIO(response.read()))
        original=json.loads(archive.read('references-collected.json'))
        current=json.loads(archive.read('references-analysis.json'))
        self.assertEqual(collected,original['reference_set_sha256'])
        self.assertNotEqual(collected,current['reference_set_sha256'])
        for bundle in (original,current):
            self.assertEqual(bundle['reference_set_sha256'],fp.digest(fp.dumps(bundle['entries'])))
            self.assertEqual(bundle['algorithm_version'],collector.VERSION)
        rows=[json.loads(line) for line in archive.read('results.jsonl').splitlines()]
        replay=fp.tokenizer_matches(rows,current['entries'],app.probe_hashes())
        self.assertEqual(replay,self.server.lab.load(target)['tokref'])
        self.assertIn(b'reference',archive.read('report-collected.md'))
        self.assertNotEqual(archive.read('report.md'),archive.read('report-collected.md'))


if __name__=='__main__':
    unittest.main()
