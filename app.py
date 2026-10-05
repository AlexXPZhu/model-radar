#!/usr/bin/env python3
"""Local UI for Model Fingerprint Lab. Python 3.10+, no external dependencies."""
import argparse
import copy
import datetime as dt
import io
import json
import math
import os
from pathlib import Path
import random
import re
import secrets
import statistics
import threading
import time
import urllib.parse
import webbrowser
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import collector as core

ROOT = Path(__file__).resolve().parent
PRESETS = {
    'quick': ['baseline', 'instruction', 'math', 'code_trace', 'chinese_order', 'stream_usage'],
    'compatibility': ['baseline']+[c['id'] for c in core.suite(3) if c['category'] == 'compatibility'],
    'full': [c['id'] for c in core.suite(3)],
}


def median(values):
    return round(statistics.median(values), 3) if values else None


def finite_number(value, low, high, name, integer=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(name+' 必须是有效数字')
    if not low <= value <= high or (integer and int(value) != value):
        raise ValueError(f'{name} 必须在 {low}～{high} 之间'+('且为整数' if integer else ''))
    return int(value) if integer else value


def validate_config(data):
    model = str(data.get('model', '')).strip()
    if not model or len(model) > 200:
        raise ValueError('请填写模型 ID（最多 200 字符）')
    url = core.endpoint(str(data.get('base_url', '')).strip())
    key = core.validate_key(str(data.get('api_key', '')), model)
    lines = finite_number(data.get('long_lines', 800), 3, 10000, '长文本行数', True)
    selected = data.get('cases', PRESETS['quick'])
    if not isinstance(selected, list) or not selected or any(not isinstance(x, str) for x in selected):
        raise ValueError('请至少选择一个有效测试项')
    cases = [c for c in core.suite(lines) if c['id'] in selected]
    if set(selected) != {c['id'] for c in cases}:
        raise ValueError('包含未知测试项')
    config = dict(endpoint=url, model=model, cases=cases,
                  label=str(data.get('label', '')).strip()[:100] or model,
                  repeats=finite_number(data.get('repeats', 3), 1, 20, '重复次数', True),
                  timeout=finite_number(data.get('timeout', 90), 1, 600, '读取超时'),
                  interval=finite_number(data.get('interval', .5), 0, 60, '请求间隔'),
                  long_lines=lines, shuffle_seed=20260929, version=core.VERSION)
    config['corpus_sha256'] = core.digest(core.dumps(cases))
    config['planned_requests'] = len(cases)*config['repeats']
    return config, key


def summarize(rows):
    groups = {}
    anomalies = []
    for row in rows:
        groups.setdefault(row['case_id'], []).append(row)
    summary = []
    for name, group in groups.items():
        good = [r for r in group if r.get('complete')]
        checked = [r for r in good if r.get('validation_pass') is not None]
        prompt = sorted({r['usage']['prompt_tokens'] for r in good
                         if isinstance(r.get('usage'), dict) and type(r['usage'].get('prompt_tokens')) is int})
        hashes = {r.get('request_sha256') for r in good}
        if len(prompt) > 1 and len(hashes) == 1 and None not in hashes:
            anomalies.append({'case_id': name, 'kind': 'usage',
                'message': f'相同请求体的输入计数出现差异：{prompt}。需核对隐藏上下文、统计口径或处理路径；不能据此确认换模。'})
        if name == 'stop' and any('|' in r.get('text', '') for r in good):
            anomalies.append({'case_id': name, 'kind': 'parameter', 'message': '停止符仍出现在正文中，调用链未兑现该停止条件。'})
        if name in ('logprobs', 'top_logprobs') and good and not any(r.get('logprobs_present') for r in good):
            anomalies.append({'case_id': name, 'kind': 'parameter', 'message': '请求被接受，但成功响应均没有概率数据。'})
        summary.append(dict(case_id=name, category=group[0].get('category'), count=len(group),
            complete=len(good), checked=len(checked), passed=sum(bool(r['validation_pass']) for r in checked),
            unique_texts=len({r.get('output_sha256', core.digest(r.get('text',''))) for r in good}),
            normalized_unique_texts=len({r.get('text','').strip() for r in good}),
            median_s=median([r['total_s'] for r in good if type(r.get('total_s')) in (float,int)]),
            ttft_s=median([r['ttft_s'] for r in good if type(r.get('ttft_s')) in (float,int)]),
            prompt_tokens=prompt))
    good = [r for r in rows if r.get('complete')]
    return dict(count=len(rows), complete=len(good), failed=len(rows)-len(good),
        median_s=median([r['total_s'] for r in good if type(r.get('total_s')) in (float,int)]),
        ttft_s=median([r['ttft_s'] for r in good if type(r.get('ttft_s')) in (float,int)]),
        cases=summary, anomalies=anomalies)


def safe_row(row, key):
    row['headers'] = [(k, '[REDACTED]' if any(x in k.lower() for x in
        ('cookie', 'authorization', 'api-key', 'api_key', 'token', 'secret')) else v)
        for k,v in row.get('headers', [])]
    return core.redact(row, key)


class Lab:
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.cancel = threading.Event()
        self.state = {'status': 'idle', 'run_id': None, 'current': None, 'completed': 0,
                      'planned': 0, 'message': '准备开始', 'started_at': None}
        self.worker = None

    def start(self, data):
        config, key = validate_config(data)
        with self.lock:
            if self.state['status'] in ('running','stopping'):
                raise ValueError('已有任务正在运行，请等待或停止后再试')
            run_id = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4)
            config.update(run_id=run_id, created_at=dt.datetime.now(dt.timezone.utc).isoformat(), status='running')
            out = self.data_dir/run_id
            (out/'raw').mkdir(parents=True)
            self.write_manifest(out, core.redact(config, key))
            self.cancel.clear()
            self.state = dict(status='running',run_id=run_id,current=None,completed=0,
                planned=config['planned_requests'],message='正在连接端点',started_at=time.time())
            self.worker = threading.Thread(target=self.run, args=(config,key,out), daemon=True)
            self.worker.start()
        return {'run_id':run_id}

    def write_manifest(self, out, config):
        tmp = out/'manifest.tmp'
        tmp.write_text(core.dumps(config), encoding='utf-8')
        tmp.replace(out/'manifest.json')

    def stop(self):
        with self.lock:
            if self.state['status'] == 'running':
                self.cancel.set()
                self.state.update(status='stopping', message='等待当前请求结束；之后不再发起请求')
        return self.snapshot()

    def snapshot(self):
        with self.lock:
            return copy.deepcopy(self.state)

    def run(self, config, key, out):
        rows = []
        status, message = 'completed', '检测完成'
        try:
            schedule = [(c,i+1) for i in range(config['repeats']) for c in config['cases']]
            random.Random(config['shuffle_seed']).shuffle(schedule)
            # Authenticate with the baseline first if it is selected.
            schedule.sort(key=lambda entry: entry[0]['id'] != 'baseline')
            for n,(case, repeat) in enumerate(schedule, 1):
                if self.cancel.is_set():
                    break
                with self.lock:
                    self.state['current'] = {'case_id':case['id'], 'repeat':repeat, 'started_at':time.time()}
                payload = dict(model=config['model'], messages=[{'role':'user','content':case['prompt']}], **case['params'])
                row, raw = core.collect(config['endpoint'], key, payload, config['timeout'])
                raw_file = f'raw/{n:04d}_{case["id"]}_{repeat}.body'
                (out/raw_file).write_bytes(raw.replace(key.encode(), b'[REDACTED]'))
                row.update(run_id=config['run_id'],case_id=case['id'],category=case['category'],repeat=repeat,
                    recorded_at=dt.datetime.now(dt.timezone.utc).isoformat(),request=payload,
                    request_sha256=core.digest(core.dumps(payload)),raw_file=raw_file,
                    validation_pass=core.check(case,row),
                    normalized_validation_pass=(row['text'].strip() == case['expected'])
                        if row['complete'] and case['expected'] is not None else None)
                row = safe_row(row,key)
                with self.lock:
                    with (out/'results.jsonl').open('a', encoding='utf-8') as f:
                        f.write(core.dumps(row)+'\n')
                    rows.append(row)
                    self.state['completed'] = len(rows)
                core.reports(out, rows, config['planned_requests'])
                (out/'analysis.json').write_text(core.dumps(summarize(rows)),encoding='utf-8')
                if row['http_status'] in (401,403):
                    status, message = 'failed', '鉴权或权限失败，已停止。请核对端点和密钥。'
                    break
                if self.cancel.wait(config['interval']):
                    break
            if self.cancel.is_set():
                status, message = 'stopped', '任务已停止，已保存完成的请求'
            elif status == 'completed' and any(not r['complete'] for r in rows):
                message = '检测完成，部分请求失败；可查看逐次证据'
        except Exception as e:
            status, message = 'failed', core.redact(type(e).__name__+': '+str(e),key)
        finally:
            try:
                core.reports(out, rows, config['planned_requests'])
                analysis = summarize(rows)
                (out/'analysis.json').write_text(core.dumps(analysis),encoding='utf-8')
                with (out/'report.md').open('a',encoding='utf-8') as f:
                    f.write('\n## 用量与参数异常线索\n\n')
                    for a in analysis['anomalies']:
                        f.write('- '+core.md(a['case_id'])+'：'+core.md(a['message'])+'\n')
                    f.write('\n完整响应的延迟中位数不包含失败调用；UI 的精确检查包含空白差异。\n')
                config.update(status=status,message=message,completed_requests=len(rows))
                self.write_manifest(out,core.redact(config,key))
            finally:
                key = ''
                with self.lock:
                    self.state.update(status=status,message=message,current=None)

    def resolve(self, run_id):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', run_id):
            raise ValueError('无效记录 ID')
        path = self.data_dir/run_id
        if not path.is_dir() or path.is_symlink():
            raise ValueError('记录不存在')
        return path

    def load(self, run_id):
        with self.lock:
            out = self.resolve(run_id)
            manifest = json.loads((out/'manifest.json').read_text(encoding='utf-8-sig'))
            rows = []
            if (out/'results.jsonl').exists():
                for line in (out/'results.jsonl').read_text(encoding='utf-8-sig').splitlines():
                    if line.strip():
                        rows.append(json.loads(line))
            report = (out/'report.md').read_text(encoding='utf-8') if (out/'report.md').exists() else ''
            return dict(manifest=manifest,rows=rows,summary=summarize(rows),report=report)

    def history(self):
        history = []
        for out in sorted(self.data_dir.iterdir(), reverse=True):
            if out.is_dir() and not out.is_symlink() and (out/'manifest.json').exists():
                try:
                    item = self.load(out.name)
                    m = item['manifest']
                    history.append(dict(run_id=out.name, label=m.get('label',m.get('model')),model=m.get('model'),
                        created_at=m.get('created_at',out.name),status=m.get('status','imported'),
                        planned=m.get('planned_requests',len(item['rows'])),summary=item['summary']))
                except (ValueError,OSError,KeyError):
                    continue
        return history

    def import_jsonl(self, data):
        """Import only supplied evidence, never execute it or trust its raw paths."""
        text = data.get('text', '')
        if not isinstance(text,str) or len(text.encode()) > 20_000_000:
            raise ValueError('仅支持 20 MB 以下的 JSONL')
        rows = []
        for number, line in enumerate(text.lstrip('\ufeff').splitlines(),1):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
                if not isinstance(r,dict) or not isinstance(r.get('case_id'),str) or not isinstance(r.get('text',''),str):
                    raise ValueError()
                # Rebuild safe, supported fields; imports cannot introduce file paths or credentials.
                keep = ['case_id','category','repeat','http_status','complete','http_ok','model',
                    'system_fingerprint','usage','text','ttft_s','total_s','finish_reasons','error',
                    'request_sha256','output_sha256','response_ids','logprobs_present','stream_observed']
                r = {k:r[k] for k in keep if k in r}
                r.setdefault('category','imported')
                for field,default in [('model',None),('system_fingerprint',None),('logprobs_present',False),('stream_observed',False),('usage',None)]:
                    r.setdefault(field,default)
                if not isinstance(r.get('category'), str):
                    r['category'] = 'imported'
                for field in ('model','system_fingerprint','request_sha256'):
                    if not isinstance(r.get(field),str):
                        r[field] = None
                if not isinstance(r.get('usage'),dict):
                    r['usage'] = None
                if r.get('usage'):
                    for field in ('prompt_tokens','completion_tokens','total_tokens'):
                        if type(r['usage'].get(field)) is not int:
                            r['usage'].pop(field,None)
                r.setdefault('http_ok',r.get('http_status') == 200)
                r['complete'] = r.get('complete') is True
                for timing in ('total_s','ttft_s'):
                    v = r.get(timing)
                    if type(v) not in (int,float) or not math.isfinite(v) or v < 0:
                        r[timing] = None
                r['validation_pass'] = None
                r['raw_file'] = None
                r['output_sha256'] = core.digest(r.get('text',''))
                rows.append(r)
            except (ValueError,TypeError,KeyError):
                raise ValueError(f'第 {number} 行不是有效的采集记录') from None
        if not rows or len(rows) > 5000:
            raise ValueError('导入记录数量必须在 1～5000 之间')
        # Check against current exact-answer rules, including legacy 1.x exports.
        cases = {c['id']:c for c in core.suite(800)}
        for r in rows:
            if r['case_id'] in cases:
                r['validation_pass'] = core.check(cases[r['case_id']],r)
        run_id = 'import-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4)
        out = self.data_dir/run_id
        out.mkdir()
        self.write_manifest(out,dict(run_id=run_id,label=str(data.get('label','历史导入'))[:100],
            status='imported',model=rows[0].get('model'),planned_requests=len(rows),
            corpus_sha256=None,version=core.VERSION,created_at=dt.datetime.now(dt.timezone.utc).isoformat(),
            note='只导入逐次记录；无原始正文文件。固定答案按 2.0 精确规则重新检查。'))
        (out/'results.jsonl').write_text(''.join(core.dumps(r)+'\n' for r in rows),encoding='utf-8')
        core.reports(out,rows,len(rows))
        return {'run_id':run_id}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Do not log request bodies, session URLs, or API credentials.

    def send(self, status, body, content_type='application/json; charset=utf-8', extra=None):
        if not isinstance(body,bytes):
            body = (core.dumps(body) if content_type.startswith('application/json') else body).encode()
        self.send_response(status)
        for k,v in {'Content-Type':content_type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
                    'Referrer-Policy':'no-referrer','Content-Security-Policy':
                    "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'", **(extra or {})}.items():
            self.send_header(k,v)
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError,ConnectionResetError):
            pass

    def allowed(self, authenticated=True):
        # Exact Host and Origin plus per-launch token protect the local control API.
        if self.headers.get('Host') != self.server.host_header:
            return False
        origin = self.headers.get('Origin')
        if origin and origin != self.server.origin:
            return False
        if self.headers.get('Sec-Fetch-Site') == 'cross-site':
            return False
        if authenticated:
            return secrets.compare_digest(self.headers.get('X-Lab-Token',''),self.server.token)
        return True

    def do_GET(self):
        if not self.allowed(False):
            return self.send(403,{'error':'本地访问校验失败'})
        path = urllib.parse.urlsplit(self.path).path
        if path in ('/','/app.js','/style.css'):
            file = {'/':'index.html','/app.js':'app.js','/style.css':'style.css'}[path]
            content = (ROOT/'web'/file).read_bytes()
            if path == '/':
                content = content.replace(b'__LAB_TOKEN__', self.server.token.encode())
            return self.send(200,content,{'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}[path])
        if not self.allowed():
            return self.send(403,{'error':'会话已失效，请刷新本地页面'})
        try:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            lab = self.server.lab
            if path == '/api/meta':
                return self.send(200,dict(version=core.VERSION,cases=core.suite(800),presets=PRESETS,data_dir=str(lab.data_dir)))
            if path == '/api/state':
                return self.send(200,lab.snapshot())
            if path == '/api/history':
                return self.send(200,lab.history())
            if path == '/api/run':
                return self.send(200,lab.load(query.get('id',[''])[0]))
            if path == '/api/export':
                run_id = query.get('id',[''])[0]
                out = lab.resolve(run_id)
                if lab.snapshot()['run_id'] == run_id and lab.snapshot()['status'] in ('running','stopping'):
                    raise ValueError('请等待任务结束后再导出')
                buf = io.BytesIO()
                with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as archive:
                    for f in out.rglob('*'):
                        if f.is_file() and not f.is_symlink() and f.suffix != '.tmp':
                            archive.write(f, f.relative_to(out))
                return self.send(200,buf.getvalue(),'application/zip',{'Content-Disposition':f'attachment; filename="{run_id}.zip"'})
            if path == '/api/raw':
                item = lab.load(query.get('id',[''])[0])
                index = int(query.get('index',['-1'])[0])
                if not 0 <= index < len(item['rows']):
                    raise ValueError('记录不存在')
                name = item['rows'][index].get('raw_file')
                if not name:
                    raise ValueError('导入记录没有原始正文文件')
                root = lab.resolve(query['id'][0]).resolve()
                f = (root/name).resolve()
                if not f.is_relative_to(root/'raw') or not f.is_file() or f.is_symlink():
                    raise ValueError('原始文件不存在')
                return self.send(200,f.read_bytes(),'text/plain; charset=utf-8')
            self.send(404,{'error':'页面不存在'})
        except (ValueError,KeyError,OSError) as e:
            self.send(400,{'error':str(e)})

    def do_POST(self):
        if not self.allowed():
            # Drain bounded bodies before closing; unread bytes can cause a TCP reset on Windows.
            try:
                length = int(self.headers.get('Content-Length','0'))
                if 0 < length <= 25_000_000:
                    self.rfile.read(length)
            except (ValueError,OSError):
                pass
            return self.send(403,{'error':'本地访问校验失败，请刷新页面'})
        try:
            if not self.headers.get('Content-Type','').startswith('application/json'):
                raise ValueError('只接受 JSON 请求')
            length = int(self.headers.get('Content-Length','0'))
            if not 0 < length <= 25_000_000:
                raise ValueError('请求过大或为空')
            data = json.loads(self.rfile.read(length))
            if not isinstance(data,dict):
                raise ValueError('请求格式错误')
            path = urllib.parse.urlsplit(self.path).path
            if path == '/api/start':
                result = self.server.lab.start(data)
            elif path == '/api/stop':
                result = self.server.lab.stop()
            elif path == '/api/import':
                result = self.server.lab.import_jsonl(data)
            else:
                return self.send(404,{'error':'接口不存在'})
            self.send(200,result)
        except (ValueError,TypeError,OSError) as e:
            self.send(400,{'error':str(e)})


def make_server(data_dir, port=0):
    server = ThreadingHTTPServer(('127.0.0.1',port),Handler)
    server.daemon_threads = True
    server.lab = Lab(data_dir)
    server.token = secrets.token_urlsafe(32)
    server.host_header = '127.0.0.1:'+str(server.server_port)
    server.origin = 'http://'+server.host_header
    return server


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port',type=int,default=0,help='0 selects an available local port')
    p.add_argument('--data-dir',default=str(ROOT/'data'))
    p.add_argument('--no-browser',action='store_true')
    args = p.parse_args()
    server = make_server(args.data_dir,args.port)
    print('ModelRadar '+core.VERSION+'\n'+server.origin, flush=True)
    print('Local data: '+str(server.lab.data_dir)+'\nPress Ctrl+C to exit.', flush=True)
    if not args.no_browser:
        webbrowser.open(server.origin)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.lab.stop()
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
