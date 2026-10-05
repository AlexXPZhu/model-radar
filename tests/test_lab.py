import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import app
import collector

KEY='mock-private-key'

class MockProvider(BaseHTTPRequestHandler):
    calls=[]
    def log_message(self,*a): pass
    def do_POST(self):
        p=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.calls.append(p)
        if self.headers.get('Authorization') != 'Bearer '+KEY:
            self.send_response(401);self.end_headers()
            self.wfile.write(b'{"error":{"message":"invalid credential"}}')
            return
        self.send_response(200)
        self.send_header('Set-Cookie','secret-cookie')
        self.send_header('Content-Type','text/event-stream' if p.get('stream') else 'application/json')
        self.end_headers()
        if self.path.startswith('/slow'):
            time.sleep(.1)
        prompt=p['messages'][0]['content']
        text='hello' if 'hello' in prompt else '1 2 3 4 5 6 7 8 9 10'
        obj=dict(id='resp_mock',model='mock',usage={'prompt_tokens':10,'completion_tokens':2},
                 choices=[{'index':0,'message':{'content':text},'finish_reason':'stop'}])
        if p.get('stream'):
            for chunk in [dict(id='resp_mock',choices=[{'delta':{'role':'assistant'}}]),
                          dict(id='resp_mock',choices=[{'delta':{'content':text}}]),
                          dict(usage=obj['usage'],choices=[{'delta':{},'finish_reason':'stop'}])]:
                self.wfile.write(('data: '+json.dumps(chunk)+'\n\n').encode());self.wfile.flush()
            self.wfile.write(b'data: [DONE]\n\n')
        else:
            self.wfile.write(json.dumps(obj).encode())


class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock=ThreadingHTTPServer(('127.0.0.1',0),MockProvider)
        threading.Thread(target=cls.mock.serve_forever,daemon=True).start()
        cls.provider='http://127.0.0.1:'+str(cls.mock.server_port)+'/v1'
    @classmethod
    def tearDownClass(cls):
        cls.mock.shutdown();cls.mock.server_close()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.server=app.make_server(self.temp.name)
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
    def tearDown(self):
        if self.server.lab.worker:self.server.lab.worker.join(3)
        self.server.shutdown();self.server.server_close();self.temp.cleanup()
    def config(self,**extra):
        return dict(base_url=self.provider,model='mock-model',api_key=KEY,cases=['baseline','stream_usage'],repeats=2,interval=0,timeout=2,**extra)
    def request(self,path,body=None,headers=None):
        req=urllib.request.Request(self.server.origin+path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'X-Lab-Token':self.server.token,'Content-Type':'application/json',**(headers or {})})
        return urllib.request.urlopen(req,timeout=5)
    def wait_run(self):
        self.server.lab.worker.join(4)
        self.assertFalse(self.server.lab.worker.is_alive())
    def test_full_run_stream_and_zip(self):
        with self.request('/api/start',self.config()) as response:
            run_id=json.load(response)['run_id']
        self.wait_run()
        run=self.server.lab.load(run_id)
        self.assertEqual(run['summary']['complete'],4)
        for r in run['rows']:
            self.assertEqual(r['response_ids'],['resp_mock'])
            self.assertNotIn(KEY,json.dumps(r))
            self.assertNotIn('secret-cookie',json.dumps(r))
        stream=[r for r in run['rows'] if r['case_id']=='stream_usage'][0]
        self.assertIsNotNone(stream['ttft_s'])
        with self.request('/api/export?id='+run_id) as response:
            archive=zipfile.ZipFile(io.BytesIO(response.read()))
        self.assertIn('report.md',archive.namelist())
        self.assertEqual(len([n for n in archive.namelist() if n.startswith('raw/')]),4)
        for path in Path(self.temp.name).rglob('*'):
            if path.is_file():self.assertNotIn(KEY.encode(),path.read_bytes())
    def test_auth_failure_stops(self):
        config=self.config();config['api_key']='wrong-key'
        run_id=self.server.lab.start(config)['run_id'];self.wait_run()
        run=self.server.lab.load(run_id)
        self.assertEqual(len(run['rows']),1)
        self.assertEqual(run['manifest']['status'],'failed')
        self.assertEqual(run['rows'][0]['http_status'],401)
    def test_stop_preserves_current_request(self):
        config=self.config();config['base_url']=self.provider.replace('/v1','/slow');config['repeats']=20
        run_id=self.server.lab.start(config)['run_id']
        time.sleep(.02);self.server.lab.stop();self.wait_run()
        run=self.server.lab.load(run_id)
        self.assertEqual(run['manifest']['status'],'stopped')
        self.assertLessEqual(len(run['rows']),1)
    def test_api_token_and_origin(self):
        for headers in [{'X-Lab-Token':''},{'Origin':'https://evil.example'}, {'Host':'evil.example'},{'Sec-Fetch-Site':'cross-site'}]:
            with self.assertRaises(urllib.error.HTTPError) as caught:
                self.request('/api/start',self.config(),headers)
            self.assertEqual(caught.exception.code,403)
        self.assertEqual(self.server.lab.snapshot()['status'],'idle')
    def test_import_strict_scoring_and_paths(self):
        r=dict(case_id='baseline',repeat=1,http_status=200,complete=True,http_ok=True,
               text=' hello',total_s=1,ttft_s=None,usage={'prompt_tokens':34},request_sha256='same',
               raw_file='../../secret',validation_pass=True,api_key=KEY)
        second=dict(r,text='hello',usage={'prompt_tokens':4414})
        result=self.server.lab.import_jsonl({'text':json.dumps(r)+'\n'+json.dumps(second)})
        run=self.server.lab.load(result['run_id'])
        self.assertFalse(run['rows'][0]['validation_pass'])
        self.assertTrue(run['rows'][1]['validation_pass'])
        self.assertIsNone(run['rows'][0]['raw_file'])
        self.assertNotIn('api_key',run['rows'][0])
        self.assertEqual(len(run['summary']['anomalies']),1)
        with self.assertRaises(ValueError):self.server.lab.resolve('../secret')
    def test_import_invalid_input(self):
        for text in ['not json','{}','[]','']:
            with self.assertRaises(ValueError):self.server.lab.import_jsonl({'text':text})
    def test_limits_and_key(self):
        for field,value in [('repeats',0),('repeats',float('nan')),('timeout',-1),('interval',100),('cases',['unknown']),('api_key','Bearer abc')]:
            config=self.config();config[field]=value
            with self.assertRaises(ValueError):app.validate_config(config)
    def test_exact_validation(self):
        case=collector.suite(3)[0]
        self.assertTrue(collector.check(case,dict(complete=True,text='hello')))
        self.assertFalse(collector.check(case,dict(complete=True,text=' hello')))
    def test_idempotent_read_and_static(self):
        with self.request('/') as response:
            self.assertIn(self.server.token.encode(),response.read())
            self.assertIn("frame-ancestors 'none'",response.headers['Content-Security-Policy'])
        with self.request('/api/meta') as response:
            self.assertEqual(len(json.load(response)['cases']),24)
    def test_active_run_rejected(self):
        config=self.config();config['base_url']=self.provider.replace('/v1','/slow')
        self.server.lab.start(config)
        with self.assertRaises(ValueError):self.server.lab.start(config)
        self.server.lab.stop();self.wait_run()


if __name__=='__main__':unittest.main(verbosity=2)
