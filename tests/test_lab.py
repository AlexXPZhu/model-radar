import io
import json
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import app
import collector
import fingerprint

KEY='mock-private-key'

class MockProvider(BaseHTTPRequestHandler):
    calls=[]
    def log_message(self,*a): pass
    def do_GET(self):
        if self.headers.get('Authorization') != 'Bearer '+KEY:
            self.send_response(401);self.end_headers()
            self.wfile.write(b'{"error":{"message":"invalid credential"}}')
            return
        if self.path == '/v1/models':
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('X-Request-Id','models-1')
            self.end_headers()
            self.wfile.write(json.dumps({'object':'list','data':[
                {'id':'mock-model'},{'id':'mock-model-mini'},{'id':'other/thing'}]}).encode())
            return
        self.send_response(404);self.end_headers();self.wfile.write(b'{}')
    def do_POST(self):
        p=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.calls.append(p)
        if self.headers.get('Authorization') != 'Bearer '+KEY:
            self.send_response(401);self.end_headers()
            self.wfile.write(b'{"error":{"message":"invalid credential"}}')
            return
        self.send_response(200)
        self.send_header('Set-Cookie','secret-cookie')
        self.send_header('X-Tokenizer-Version','tiktoken-1')
        self.send_header('X-Session-Id','sess-1')
        self.send_header('Content-Type','text/event-stream' if p.get('stream') else 'application/json')
        self.end_headers()
        if self.path.startswith('/slow'):
            time.sleep(.1)
        prompt=p['messages'][0]['content']
        text='hello' if 'hello' in prompt else '1 2 3 4 5 6 7 8 9 10'
        # Count tokens from the text so tokenizer probes differ; /alt mimics a
        # different vocabulary plus a larger hidden template.
        tokens=9+len(prompt)//2 if self.path.startswith('/alt') else 5+len(prompt)//3
        obj=dict(id='chatcmpl-abc123',model='mock-model',usage={'prompt_tokens':tokens,'completion_tokens':2},
                 choices=[{'index':0,'message':{'content':text},'finish_reason':'stop'}])
        if p.get('logprobs'):
            # Token slicing deliberately differs from the text, which is the point
            # of the probe: it exposes the server-side tokenizer.
            obj['choices'][0]['logprobs']={'content':[{'token':'he','logprob':-0.1},{'token':'llo','logprob':-0.2}]}
        if p.get('stream'):
            for chunk in [dict(id='chatcmpl-abc123',choices=[{'delta':{'role':'assistant'}}]),
                          dict(id='chatcmpl-abc123',choices=[{'delta':{'content':text}}]),
                          dict(usage=obj['usage'],choices=[{'delta':{},'finish_reason':'stop'}])]:
                self.wfile.write(('data: '+json.dumps(chunk)+'\n\n').encode());self.wfile.flush()
            self.wfile.write(b'data: [DONE]\n\n')
        else:
            self.wfile.write(json.dumps(obj).encode())


class LabHarness:
    """Mock provider plus a local UI server, shared by the test classes."""
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
        base=dict(base_url=self.provider,model='mock-model',api_key=KEY,
                  cases=['baseline','stream_usage'],repeats=2,interval=0,timeout=2)
        base.update(extra);return base
    def request(self,path,body=None,headers=None,token=None):
        req=urllib.request.Request(self.server.origin+path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'X-Lab-Token':self.server.token if token is None else token,
                     'Content-Type':'application/json',**(headers or {})})
        return urllib.request.urlopen(req,timeout=5)
    def wait_run(self):
        self.server.lab.worker.join(4)
        self.assertFalse(self.server.lab.worker.is_alive())


class LabTests(LabHarness,unittest.TestCase):
    def test_full_run_stream_and_zip(self):
        with self.request('/api/start',self.config()) as response:
            run_id=json.load(response)['run_id']
        self.wait_run()
        run=self.server.lab.load(run_id)
        self.assertEqual(run['summary']['complete'],4)
        for r in run['rows']:
            self.assertEqual(r['response_ids'],['chatcmpl-abc123'])
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
            self.assertEqual(len(json.load(response)['cases']),len(collector.suite(3)))
    def test_active_run_rejected(self):
        config=self.config();config['base_url']=self.provider.replace('/v1','/slow')
        self.server.lab.start(config)
        with self.assertRaises(ValueError):self.server.lab.start(config)
        self.server.lab.stop();self.wait_run()


class UiContractTests(unittest.TestCase):
    """The UI has no build step, so a missing element id fails silently at runtime."""
    def setUp(self):
        self.html=(Path(app.ROOT)/'web'/'index.html').read_text(encoding='utf-8')
        self.js=(Path(app.ROOT)/'web'/'app.js').read_text(encoding='utf-8')
    def test_every_looked_up_id_exists(self):
        ids=set(re.findall(r"id=[\"']([A-Za-z0-9_-]+)[\"']",self.html))
        used=set(re.findall(r"\$\('#([A-Za-z0-9_-]+)'\)",self.js))
        self.assertTrue(used)
        self.assertEqual(sorted(used-ids),[],'app.js 引用了不存在的元素 id')
    def test_presets_rendered_in_page_match_meta(self):
        for name in app.PRESETS:
            self.assertIn(f'data-preset="{name}"',self.html,name)
    def test_new_controls_are_present(self):
        for element in ('fetchModels','modelPicker','modelList','modelFilter','modelSummary','signalsPanel'):
            self.assertIn(f'id="{element}"',self.html,element)


class SignalTests(unittest.TestCase):
    """Unit coverage for the extraction layer, which needs no server."""
    def test_header_redaction_keeps_side_channels(self):
        kept=dict(fingerprint.safe_headers([('X-Tokenizer-Version','tiktoken-1'),
            ('X-RateLimit-Remaining-Tokens','99'),('X-Request-Id','r-1'),('Retry-After','3')]))
        self.assertEqual(kept['X-Tokenizer-Version'],'tiktoken-1')
        self.assertEqual(kept['X-RateLimit-Remaining-Tokens'],'99')
        redacted=dict(fingerprint.safe_headers([('Set-Cookie','a=b'),('X-Session-Id','s'),
            ('Authentication-Info','x'),('X-Amz-Security-Token','t'),('X-Api-Key','k')]))
        for name in ('Set-Cookie','X-Session-Id','Authentication-Info','X-Amz-Security-Token','X-Api-Key'):
            self.assertEqual(redacted[name],'[REDACTED]',name)
    def test_response_id_shape(self):
        self.assertEqual(fingerprint.describe_id('chatcmpl-ABC123')['prefix'],'chatcmpl-')
        self.assertEqual(fingerprint.describe_id('gen-1234abc')['kind'],'prefix+hex')
        self.assertEqual(fingerprint.describe_id('msg_01XY')['prefix'],'msg_')
        # A bare hex fragment must not be read as an id prefix.
        self.assertIsNone(fingerprint.describe_id('0192abcdef')['prefix'])
        self.assertIsNone(fingerprint.describe_id('plain')['prefix'])
    def test_model_list_shapes(self):
        self.assertEqual(collector.parse_model_list(b'[{"id":"a"},{"id":"a"},"b"]'),(['a','b'],'array'))
        self.assertEqual(collector.parse_model_list(b'{"models":[{"name":"m"}]}'),(['m'],'object.models'))
        self.assertEqual(collector.parse_model_list(b'{"object":"list"}'),([],'unknown'))
        self.assertEqual(collector.parse_model_list(b'not json'),([],'unparsed'))
    def test_model_urls_honour_custom_prefix(self):
        urls=collector.model_urls('https://h.example/api/proxy/v1')
        self.assertEqual(urls[0],'https://h.example/api/proxy/v1/models')
        self.assertIn('https://h.example/api/proxy/models',urls)
        self.assertEqual(collector.model_urls('https://h.example/v1/chat/completions')[0],
                         'https://h.example/v1/models')
    def test_match_model_tolerates_vendor_prefix(self):
        self.assertTrue(collector.match_model('claude-opus',['anthropic/claude-opus'])['loose'])
        self.assertTrue(collector.match_model('gpt-4o',['gpt-4o'])['matched'])
        self.assertFalse(collector.match_model('claude-opus',['anthropic/claude-sonnet'])['matched'])
        self.assertFalse(collector.match_model('x',['unrelated'])['matched'])
    def test_stream_timeline_profiles(self):
        burst=dict(stream_observed=True,events=[{'elapsed_s':t,'data':'x'*20} for t in (0.1,0.1,0.1,0.1,0.1)])
        self.assertEqual(fingerprint.stream_timeline(burst)['profile'],'单批缓冲')
        steady=dict(stream_observed=True,events=[{'elapsed_s':0.1*i,'data':'x'} for i in range(6)])
        self.assertEqual(fingerprint.stream_timeline(steady)['profile'],'平稳')
        self.assertEqual(fingerprint.stream_timeline(dict(events=[]))['chunks'],0)
    def test_tokenizer_cross_check_counts_ignored_text(self):
        rows=[dict(case_id='tokenizer_0',complete=True,usage={'prompt_tokens':19}),
              dict(case_id='tokenizer_1',complete=True,usage={'prompt_tokens':19})]
        flagged=[s for s in fingerprint.tokenizer_signals(rows) if s['case_id']=='tokenizer_cross']
        self.assertEqual(len(flagged),1)
        ok=[dict(case_id='tokenizer_0',complete=True,usage={'prompt_tokens':19}),
            dict(case_id='tokenizer_1',complete=True,usage={'prompt_tokens':109})]
        self.assertFalse([s for s in fingerprint.tokenizer_signals(ok) if s['case_id']=='tokenizer_cross'])
    def test_agreement_flags_declared_model_mismatch(self):
        rows=[dict(case_id='baseline',model='gpt-4o',declared_model='gpt-4o-mini',response_ids=['chatcmpl-a'])]
        self.assertTrue(fingerprint.agreement(rows)['declared_model']['returned_differs'])
        same=[dict(case_id='baseline',model='gpt-4o',declared_model='gpt-4o',response_ids=['chatcmpl-a'])]
        self.assertFalse(fingerprint.agreement(same)['declared_model']['returned_differs'])


def probe_rows(counts,model='m',hashes=None):
    hashes=hashes or app.probe_hashes()
    return [dict(case_id=k,complete=True,declared_model=model,prompt_sha256=hashes[k],
                 usage={'prompt_tokens':v}) for k,v in counts.items()]


class TokenizerReferenceTests(unittest.TestCase):
    BASE={'tokenizer_base':20,'tokenizer_0':53,'tokenizer_1':164,'tokenizer_2':189,'tokenizer_4':163}
    MANIFEST=dict(status='completed',run_id='r1',endpoint='https://api.example/v1',model='m')
    def reference(self,counts=None,model='m'):
        entry=fingerprint.build_reference(probe_rows(counts or self.BASE,model),
                                          dict(self.MANIFEST,model=model),'官方 m','fam')
        entry.update(id='ref-1',source='local');return entry
    def test_hidden_context_cancels_and_is_reported(self):
        shifted={k:v+37 for k,v in self.BASE.items()}
        result=fingerprint.tokenizer_matches(probe_rows(shifted),[self.reference()])
        self.assertEqual(result['matches'][0]['level'],'exact')
        self.assertEqual(result['declared']['offset'],37)
    def test_other_tokenizer_is_flagged_against_declared_model(self):
        other={'tokenizer_base':20,'tokenizer_0':45,'tokenizer_1':116,'tokenizer_2':189,'tokenizer_4':117}
        refs=[self.reference(),dict(self.reference(other,'n'),id='ref-2',label='官方 n')]
        result=fingerprint.tokenizer_matches(probe_rows(other,'m'),refs)
        self.assertEqual(result['declared']['level'],'different')
        self.assertEqual(result['declared']['nearest']['label'],'官方 n')
    def test_off_by_one_is_near_not_exact(self):
        close=dict(self.BASE,tokenizer_1=165)
        self.assertEqual(fingerprint.tokenizer_matches(probe_rows(close),[self.reference()])['matches'][0]['level'],'near')
    def test_changed_probe_text_is_not_compared(self):
        hashes=dict(app.probe_hashes(),tokenizer_0='x',tokenizer_1='y')
        result=fingerprint.tokenizer_matches(probe_rows(self.BASE,hashes=hashes),[self.reference()])
        self.assertEqual(result['matches'],[])
    def test_too_few_probes_is_unusable(self):
        result=fingerprint.tokenizer_matches(probe_rows({'tokenizer_0':5,'tokenizer_1':9}),[self.reference()])
        self.assertFalse(result['usable'])
    def test_build_reference_refusals(self):
        rows=probe_rows(self.BASE)
        with self.assertRaises(ValueError):fingerprint.build_reference(rows,dict(self.MANIFEST,status='imported'),'x')
        with self.assertRaises(ValueError):fingerprint.build_reference(rows,dict(self.MANIFEST,status='running'),'x')
        no_base={k:v for k,v in self.BASE.items() if k!='tokenizer_base'}
        with self.assertRaises(ValueError):fingerprint.build_reference(probe_rows(no_base),self.MANIFEST,'x')
        flat=dict(self.BASE,tokenizer_2=20)
        with self.assertRaises(ValueError):fingerprint.build_reference(probe_rows(flat),self.MANIFEST,'x')
        noisy=rows+[dict(rows[1],usage={'prompt_tokens':54})]
        with self.assertRaises(ValueError):fingerprint.build_reference(noisy,self.MANIFEST,'x')
        with self.assertRaises(ValueError):fingerprint.build_reference(rows,self.MANIFEST,'  ')
    def test_valid_reference_rejects_malformed_entries(self):
        self.assertTrue(fingerprint.valid_reference(self.reference()))
        for bad in [None,{},{'label':'x','probes':{}},{'label':'x','probes':{'a':{'prompt_sha256':'h','prompt_tokens':'3'}}}]:
            self.assertFalse(fingerprint.valid_reference(bad))
    def test_unstable_counts_withhold_the_verdict(self):
        # Two repeats match the reference, a third disagrees: the run's modal
        # vector was never produced by one upstream, so no verdict is published.
        rows=probe_rows(self.BASE)+[dict(case_id='tokenizer_1',complete=True,declared_model='m',
                                         prompt_sha256=app.probe_hashes()['tokenizer_1'],
                                         usage={'prompt_tokens':600})]
        result=fingerprint.tokenizer_matches(rows,[self.reference()])
        match=result['matches'][0]
        self.assertEqual(match['level'],'unstable')
        self.assertEqual(match['provisional'],'exact')
        self.assertEqual(match['unstable'],['tokenizer_1'])
        # The offset is suppressed too: it would read as a clean comparison.
        self.assertIsNone(result['declared']['offset'])
        self.assertEqual(result['declared']['level'],'unstable')
    def test_flat_probe_is_flagged_without_reference(self):
        notes=[s for s in fingerprint.tokenizer_signals(probe_rows(dict(self.BASE,tokenizer_2=20)))
               if s['case_id']=='tokenizer_cross']
        self.assertIn('tokenizer_2',notes[0]['note'])


class ReferenceRunTests(LabHarness,unittest.TestCase):
    def run_models(self,base_url=None,model='mock-model'):
        config=self.config(cases=app.PRESETS['models'],repeats=1,model=model,base_url=base_url or self.provider)
        run_id=self.server.lab.start(config)['run_id'];self.wait_run();return run_id
    def test_reference_round_trip(self):
        ref_run=self.run_models()
        with self.request('/api/reference',{'run_id':ref_run,'label':'官方 mock','family':'mock'}) as response:
            ref=json.load(response)
        self.assertTrue((Path(self.temp.name)/'_references'/'tokenizers.json').is_file())
        # The same endpoint again: identical slicing, no extra hidden tokens.
        same=self.server.lab.load(self.run_models())
        self.assertEqual(same['tokref']['declared']['level'],'exact')
        self.assertEqual(same['tokref']['declared']['offset'],0)
        # A relay answering with another vocabulary under the same model name.
        swapped=self.server.lab.load(self.run_models(self.provider.replace('/v1','/alt/v1')))
        self.assertEqual(swapped['tokref']['declared']['level'],'different')
        self.assertIn('分词参照比对',swapped['report'])
        self.assertIn('分词不一致',swapped['report'])
        # A duplicate is refused; deletion empties the local library.
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request('/api/reference',{'run_id':ref_run,'label':'again'})
        self.assertEqual(caught.exception.code,400)
        self.server.lab.delete_reference(ref['id'])
        self.assertEqual([r for r in self.server.lab.references() if r['source']=='local'],[])
        with self.assertRaises(ValueError):self.server.lab.delete_reference(ref['id'])
    def test_report_follows_the_reference_library(self):
        official=self.run_models()
        relay=self.run_models(self.provider.replace('/v1','/alt/v1'))
        # Collected before any reference existed: the report says so.
        before=self.server.lab.load(relay)
        self.assertIn('参照库中没有可比的参照',before['report'])
        self.server.lab.add_reference({'run_id':official,'label':'官方 mock'})
        after=self.server.lab.load(relay)
        # The detail verdict and the report must not disagree, and the section
        # must be replaced rather than appended.
        self.assertEqual(after['tokref']['declared']['level'],'different')
        self.assertIn('分词不一致',after['report'])
        self.assertNotIn('参照库中没有可比的参照',after['report'])
        self.assertEqual(after['report'].count('## 分词参照比对'),1)
        # The stored evidence on disk keeps what was collected at run time.
        stored=(Path(self.temp.name)/relay/'report.md').read_text(encoding='utf-8')
        self.assertIn('参照库中没有可比的参照',stored)
        # A run collected while a reference existed records that fact, so after
        # the reference is deleted the report says what it was compared against
        # instead of silently reverting to an empty-library verdict.
        during=self.run_models(self.provider.replace('/v1','/alt/v1'))
        self.server.lab.delete_reference([r for r in self.server.lab.references()
                                          if r['source']=='local'][0]['id'])
        gone=self.server.lab.load(relay)
        self.assertIn('参照库中没有可比的参照',gone['report'])
        self.assertEqual(gone['report'].count('## 分词参照比对'),1)
        self.assertNotIn('分词不一致',gone['report'])
        after_delete=self.server.lab.load(during)
        self.assertIn('检测时为：1 条本地参照',after_delete['report'])
    def test_report_refresh_is_stable_and_spares_other_sections(self):
        run_id=self.run_models()
        stored=(Path(self.temp.name)/run_id/'report.md').read_text(encoding='utf-8')
        once=self.server.lab.load(run_id)['report']
        twice=self.server.lab.load(run_id)['report']
        self.assertEqual(once,twice)
        # Sections that belong to the run itself are carried through untouched.
        self.assertIn('## 用量与参数异常线索',once)
        self.assertIn('## 侧信道信号',once)
        head,inner,tail=app.split_report(stored)
        self.assertIn('## 用量与参数异常线索',head)
        self.assertNotIn('## 用量与参数异常线索',inner)
    def test_history_stays_light_and_skips_references(self):
        run_id=self.run_models()
        self.server.lab.add_reference({'run_id':run_id,'label':'x'})
        items=self.server.lab.history()
        self.assertEqual([i['run_id'] for i in items],[run_id])
    def test_baseline_only_run_cannot_become_reference(self):
        run_id=self.server.lab.start(self.config())['run_id'];self.wait_run()
        with self.assertRaises(ValueError):self.server.lab.add_reference({'run_id':run_id,'label':'x'})


class DiscoveryTests(LabHarness,unittest.TestCase):
    def test_discovery_records_attempts_and_redacts_key(self):
        result=self.server.lab.discover({'base_url':self.provider,'api_key':KEY,'timeout':3})
        self.assertIn('mock-model',result['models'])
        self.assertEqual(result['attempts'][0]['http_status'],200)
        self.assertEqual(result['attempts'][0]['shape'],'object.data')
        for path in Path(self.temp.name).rglob('*'):
            if path.is_file():self.assertNotIn(KEY.encode(),path.read_bytes())
        # Underscore folders are not detection runs and must stay out of history.
        self.assertEqual(self.server.lab.history(),[])
    def test_discovery_route_requires_token(self):
        query='/api/models?base_url='+urllib.parse.quote(self.provider,'')
        # A missing or wrong session token is refused before the provider is called.
        for token in ('','not-the-token'):
            with self.assertRaises(urllib.error.HTTPError) as caught:
                self.request(query,None,{'X-Provider-Key':KEY},token=token)
            self.assertEqual(caught.exception.code,403)
        with self.request(query,None,{'X-Provider-Key':KEY}) as response:
            body=json.load(response)
        self.assertIn('mock-model',body['models'])
        self.assertEqual(body['count'],3)
    def test_run_records_model_list_verdict(self):
        result=self.server.lab.discover({'base_url':self.provider,'api_key':KEY,'timeout':3})
        ref=dict(ref_id=result['ref_id'],url=result['endpoint'],count=result['count'],
                 kept=result['models'],captured_at=result['captured_at'])
        run_id=self.server.lab.start(self.config(models_ref=ref))['run_id'];self.wait_run()
        run=self.server.lab.load(run_id)
        self.assertTrue(run['manifest']['models_ref']['match']['matched'])
        self.assertTrue((Path(self.temp.name)/run_id/'models.json').is_file())
        self.assertIn('模型列表核对',run['report'])
    def test_unlisted_model_is_flagged_in_manifest(self):
        config=self.config(model='not-advertised')
        config['models_ref']=dict(ref_id=None,url='https://x/v1/models',count=2,
                                  kept=['mock-model','other/thing'],captured_at='')
        run_id=self.server.lab.start(config)['run_id'];self.wait_run()
        run=self.server.lab.load(run_id)
        self.assertIs(run['manifest']['models_ref']['match']['matched'],False)
        self.assertIn('未出现在',run['report'])
    def test_unknown_discovery_id_rejected(self):
        for bad in ['../secret','','nope']:
            with self.assertRaises(ValueError):self.server.lab.load_discovery(bad)


class SideChannelRunTests(LabHarness,unittest.TestCase):
    def test_logprobs_slicing_is_captured(self):
        config=self.config(cases=['logprobs'])
        run_id=self.server.lab.start(config)['run_id'];self.wait_run()
        run=self.server.lab.load(run_id)
        notes=[r['logprobs'] for r in run['rows'] if r.get('logprobs')]
        self.assertTrue(notes)
        self.assertEqual(notes[0]['first_tokens'],['he','llo'])
        signals=[s for s in run['summary']['logprobs'] if s['case_id']=='logprobs']
        self.assertEqual(signals[0]['distinct_tokenizations'],1)
    def test_headers_survive_but_credentials_do_not(self):
        run_id=self.server.lab.start(self.config())['run_id'];self.wait_run()
        run=self.server.lab.load(run_id)
        dumped=json.dumps(run['rows'])
        self.assertIn('tiktoken-1',dumped)          # a real side channel is kept
        self.assertNotIn('sess-1',dumped)           # a session id is not
        self.assertNotIn('secret-cookie',dumped)
        headers=run['summary']['agreement'].get('id_prefixes')
        self.assertEqual(headers['values'],['chatcmpl-'])
    def test_declared_model_is_stored_per_row(self):
        run_id=self.server.lab.start(self.config())['run_id'];self.wait_run()
        run=self.server.lab.load(run_id)
        self.assertEqual({r['declared_model'] for r in run['rows']},{'mock-model'})
        self.assertFalse(run['summary']['agreement']['declared_model']['returned_differs'])
    def test_stream_rows_carry_a_timeline(self):
        run_id=self.server.lab.start(self.config())['run_id'];self.wait_run()
        run=self.server.lab.load(run_id)
        streams=[c for c in run['summary']['cases'] if c['case_id']=='stream_usage']
        self.assertIsNotNone(streams[0]['stream_gap_p50'])
        self.assertIn('流式节奏',(Path(self.temp.name)/run_id/'report.md').read_text(encoding='utf-8'))
    def test_export_zip_is_written_once_and_report_has_signals(self):
        run_id=self.server.lab.start(self.config())['run_id'];self.wait_run()
        report=(Path(self.temp.name)/run_id/'report.md').read_text(encoding='utf-8')
        self.assertIn('## 侧信道信号',report)
        self.assertEqual(report.count('# 中转站模型行为指纹报告'),1)


if __name__=='__main__':unittest.main(verbosity=2)
