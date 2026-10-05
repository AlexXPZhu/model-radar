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
import fingerprint as fp

ROOT = Path(__file__).resolve().parent
PRESETS = {
    'quick': ['baseline', 'instruction', 'math', 'code_trace', 'chinese_order', 'stream_usage'],
    'compatibility': ['baseline']+[c['id'] for c in core.suite(3) if c['category'] == 'compatibility'],
    'full': [c['id'] for c in core.suite(3)],
    'models': ['baseline']+[c['id'] for c in core.suite(3) if c['id'].startswith('tokenizer')],
}


BUILTIN_REFERENCES = ROOT/'reference'/'tokenizers.json'


LEVEL_NAMES = {'exact': '逐 token 一致', 'near': '接近，非逐 token 一致', 'different': '不一致',
               'unstable': '计量不稳定，不下结论'}


def tokref_lines(result):
    """Markdown for the reference comparison; empty when the run has no probes."""
    if not result['usable']:
        return ''
    lines = ['', '## 分词参照比对', '']
    if result.get('snapshot'):
        lines.append(f'本节的参照库快照：{result["snapshot"]}')
    if not result['matches']:
        lines.append('参照库中没有可比的参照（需要相同文本的 tokenizer_base 加至少 3 个探针）。'
                     '请先用“分词与计量”方案对可信的官方端点检测，再把该记录设为参照。')
    else:
        lines += ['| 参照 | 系列 | 结论 | 最大差值 | 平均相对误差 | 输入偏移 |', '|---|---|---|---:|---:|---:|']
        for m in result['matches']:
            level = LEVEL_NAMES[m['level']] + (f'（按众数为 {LEVEL_NAMES[m["provisional"]]}）'
                                               if m['level'] == 'unstable' else '')
            offset = m['offset'] if m['level'] == 'exact' and m['anchored_on_base'] else '—'
            lines.append(f'| {core.md(m["label"])} | {core.md(m["family"] or "—")} | {level} | '
                         f'{m["max_abs_diff"]} | {m["mean_rel_err"]} | {offset} |')
    declared = result['declared']
    if declared:
        lines.append('')
        if declared['level'] == 'unstable':
            lines.append(f'- **本次检测的计量不稳定（{"、".join(declared["unstable"])}），因此不下分词结论。**'
                         '这些探针的重复调用给出了不同的输入计数，说明同一模型名后面不止一个上游，'
                         '或计数本身不稳定。仅按众数比较得到的“'
                         + LEVEL_NAMES.get(declared.get('provisional') or '', '未知') + '”不代表任一上游，已被替换为这个提示。')
            lines.append('- 请提高重复次数后重测；混合路由本身就是一个需要核实的线索。')
        elif declared['level'] == 'different':
            nearest = declared.get('nearest')
            lines.append(f'- **请求的模型 {core.md(declared["model"])} 与它自己的参照“{core.md(declared["label"])}”分词不一致。**'
                         + (f'最接近的是“{core.md(nearest["label"])}”（{LEVEL_NAMES[nearest["level"]]}）。' if nearest else ''))
            lines.append('- 也可能是中转站自己估算 usage（例如用 tiktoken 本地计数）而非透传上游计量；请对照原始响应核实。')
        else:
            lines.append(f'- 请求的模型 {core.md(declared["model"])} 与它的参照“{core.md(declared["label"])}”'
                         f'{LEVEL_NAMES[declared["level"]]}。')
            if declared.get('offset'):
                lines.append(f'- 空载探针比参照多计 {declared["offset"]} 个输入 token：每次请求可能附带了隐藏上下文，或计费口径不同。')
    lines += ['- 差分比较抵消了聊天模板和固定的隐藏系统提示。分词器相同只说明同一系列，'
              '例如 gpt-4o 与 gpt-4o-mini 共用分词器，不能区分同系列的大小模型。', '']
    return '\n'.join(lines)


BUILTIN_REFERENCES = ROOT/'reference'/'tokenizers.json'

# Headings a load-time refresh rebuilds, versus the sections whose text belongs
# to the run itself and is never rewritten.
REGENERATED_SECTIONS = ('## 模型列表核对', '## 分词参照比对')
RUN_SECTIONS = ('## 用量与参数异常线索',)


def split_report(report):
    """Split a report into (head, regenerable, tail).

    Only the sections in REGENERATED_SECTIONS land in the middle group. Anything
    this version does not know stays where it is, so a newer report read by an
    older build is never mangled.
    """
    head, stored, tail = [], [], []
    for line in report.split('\n'):
        if line in RUN_SECTIONS:
            head.append(line)
        elif line in REGENERATED_SECTIONS:
            (stored if not tail else tail).append(line)
        elif tail:
            tail.append(line)
        elif stored:
            stored.append(line)
        else:
            head.append(line)
    return '\n'.join(head), '\n'.join(stored), '\n'.join(tail)


def probe_hashes():
    """Current probe text hashes, for imported rows that carry no request body."""
    return {c['id']: core.digest(c['prompt']) for c in core.suite(3) if c['id'].startswith('tokenizer')}


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
    config['models_ref'] = validate_models_ref(data.get('models_ref'), model)
    return config, key


def validate_models_ref(ref, model):
    """Re-check a discovery result the UI passes back, so the server never trusts it.

    The list itself is self-reported metadata. It is stored to document what the
    endpoint advertised at run time, never to identify a backend.
    """
    if ref in (None, {}, ''):
        return None
    if not isinstance(ref, dict):
        raise ValueError('模型列表引用格式错误')
    kept = [str(x).strip()[:200] for x in ref.get('kept', []) if isinstance(x, str)]
    ref_id = ref.get('ref_id')
    # A reference either points at a stored discovery, or carries a fresh list.
    if ref_id is not None and not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', str(ref_id)):
        raise ValueError('模型列表引用 ID 无效')
    if len(kept) > 5000:
        raise ValueError('模型列表过长')
    return dict(ref_id=ref_id, url=str(ref.get('url', ''))[:500], count=len(kept),
                kept=kept, match=core.match_model(model, kept) if kept else dict(matched=None, loose=False),
                captured_at=str(ref.get('captured_at', ''))[:40])


summarize = fp.summarize


def safe_row(row, key):
    row['headers'] = fp.safe_headers(row.get('headers', []))
    return core.redact(row, key)


def models_ref_lines(ref):
    """Markdown for the advertised model list kept with the run."""
    verdict = ('未出现在该端点自报的列表中' if ref['match'].get('matched') is False else
               '出现在该端点自报的列表中' if ref['match'].get('matched') else '未能取得该端点的模型列表')
    lines = ['', '## 模型列表核对', '',
             f'- 自报列表（{ref["count"]} 项，来源 {core.md(ref["url"] or "—")}，'
             f'采集于 {core.md(ref["captured_at"] or "—")}）：请求的模型 ID {verdict}。']
    if ref['match'].get('loose'):
        lines.append('- 命中方式是去前缀匹配，列表用的是供应商限定名。')
    lines += ['- 列表由端点自报，可被改写。它只用于生成待测假设，不能证明底层模型身份。', '']
    return '\n'.join(lines)


class Lab:
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.cancel = threading.Event()
        self.state = {'status': 'idle', 'run_id': None, 'current': None, 'completed': 0,
                      'planned': 0, 'message': '准备开始', 'started_at': None}
        self.worker = None
        # Model-list probes are grouped per endpoint, so one folder holds every
        # attempt against one host instead of one folder per click.
        self.discovery_dir = self.data_dir/'_discoveries'
        self.discovery_dir.mkdir(exist_ok=True)
        self.reference_file = self.data_dir/'_references'/'tokenizers.json'

    def references(self):
        """Shipped references plus the ones built locally. Bad entries are skipped."""
        entries = []
        for path, source in ((BUILTIN_REFERENCES, 'builtin'), (self.reference_file, 'local')):
            try:
                data = json.loads(path.read_text(encoding='utf-8-sig'))
            except (OSError, ValueError):
                continue
            for entry in data.get('entries', []) if isinstance(data, dict) else []:
                if fp.valid_reference(entry):
                    entries.append(dict(entry, source=source))
        return entries

    def add_reference(self, data):
        run = self.load(str(data.get('run_id', '')))
        entry = fp.build_reference(run['rows'], run['manifest'], data.get('label'),
                                   data.get('family', ''), data.get('note', ''), fallback=probe_hashes())
        with self.lock:
            local = [e for e in self.references() if e['source'] == 'local']
            if any(e.get('run_id') == entry['run_id'] for e in local):
                raise ValueError('这条记录已经设为参照')
            entry.update(id='ref-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(3),
                         created_at=dt.datetime.now(dt.timezone.utc).isoformat())
            self.write_references(local+[entry])
        return entry

    def delete_reference(self, ref_id):
        with self.lock:
            local = [e for e in self.references() if e['source'] == 'local']
            kept = [e for e in local if e.get('id') != ref_id]
            if len(kept) == len(local):
                raise ValueError('只能删除本地参照，或该参照不存在')
            self.write_references(kept)
        return {'deleted': ref_id}

    def write_references(self, entries):
        self.reference_file.parent.mkdir(exist_ok=True)
        tmp = self.reference_file.with_suffix('.tmp')
        tmp.write_text(core.dumps(dict(schema=1, entries=[{k: v for k, v in e.items() if k != 'source'}
                                                          for e in entries])), encoding='utf-8')
        tmp.replace(self.reference_file)

    def library_snapshot(self, recorded=None):
        """Short label for the reference library a verdict was computed against.

        A comparison means nothing without knowing which library produced it, so
        every report and the UI both carry this label.
        """
        local = [r for r in self.references() if r.get('source') == 'local']
        count = len(local)
        state = f'{count} 条本地参照' if count else '本地参照库为空'
        if recorded and recorded != state:
            return f'{state}（检测时为：{recorded}）'
        return state

    def tokref_lines(self, rows, snapshot=None):
        result = fp.tokenizer_matches(rows, self.references(), probe_hashes())
        result['snapshot'] = snapshot or self.library_snapshot()
        return tokref_lines(result)

    def refresh_report(self, report, rows, manifest, run_id=None):
        """Rebuild the referenced sections from the current library.

        The stored report is the record of what was collected; the sections that
        depend on the reference library are regenerated on every read, so the
        detail view, the Markdown preview and the exported ZIP agree. Returns
        None when the report has the shape this version does not recognize, in
        which case the caller keeps the stored text as it is.
        """
        lines = report.split('\n')
        if not any(line in RUN_SECTIONS for line in lines):
            return None
        # A section is replaced whole: the heading and every line of its body,
        # up to the next heading. Dropping only the heading would leave the old
        # conclusion's body behind under the new one.
        out, dropping = [], False
        for line in lines:
            if line in REGENERATED_SECTIONS:
                fresh = self.regenerated_section(line, rows, manifest)
                if fresh:
                    out.append(fresh)
                dropping = True
                continue
            if dropping:
                if not line.startswith('#'):
                    continue
                dropping = False
            out.append(line)
        return '\n'.join(out)

    def regenerated_section(self, heading, rows, manifest):
        if heading == '## 分词参照比对':
            # Carries the library size recorded at run time, so a verdict read
            # after the library changed still says what it was compared against.
            return self.tokref_lines(rows, self.library_snapshot(manifest.get('tokref_snapshot')))
        if heading == '## 模型列表核对' and manifest.get('models_ref'):
            return models_ref_lines(manifest['models_ref'])
        return ''

    def endpoint_key(self, base_url):
        try:
            url = core.endpoint(str(base_url).strip())
        except ValueError:
            url = str(base_url).strip()
        return fp.digest(url)[:12]

    def start(self, data):
        config, key = validate_config(data)
        with self.lock:
            if self.state['status'] in ('running','stopping'):
                raise ValueError('已有任务正在运行，请等待或停止后再试')
            run_id = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4)
            config.update(run_id=run_id, created_at=dt.datetime.now(dt.timezone.utc).isoformat(), status='running')
            out = self.data_dir/run_id
            (out/'raw').mkdir(parents=True)
            self.attach_discovery(out, config.get('models_ref'))
            self.write_manifest(out, core.redact(config, key))
            self.cancel.clear()
            self.state = dict(status='running',run_id=run_id,current=None,completed=0,
                planned=config['planned_requests'],message='正在连接端点',started_at=time.time())
            self.worker = threading.Thread(target=self.run, args=(config,key,out), daemon=True)
            self.worker.start()
        return {'run_id':run_id}

    def discover(self, data):
        """Probe the endpoint's model-list routes and keep the raw evidence.

        Nothing here is a claim about a backend: the list is what the endpoint
        says about itself, the same category of metadata as the model field on a
        chat response. It exists to generate hypotheses and to be diffed later.
        """
        base_url = str(data.get('base_url', '')).strip()
        if not base_url:
            raise ValueError('请填写 Base URL')
        key = core.validate_key(str(data.get('api_key', '')), 'discovery')
        timeout = finite_number(data.get('timeout', 15), 1, 600, '读取超时')
        attempts = core.list_models(base_url, key, timeout)
        kept = next((a['models'] for a in attempts if a['models']), [])
        # Keep the ids as returned; truncate only to bound the stored payload.
        body_cap = 1_000_000
        for attempt in attempts:
            if len(attempt['body'].encode('utf-8', errors='replace')) > body_cap:
                attempt['body'] = attempt['body'][:body_cap] + '\n[TRUNCATED]'
            attempt['key_hits'] = attempt['body'].count(key) if key else 0
            attempt['body'] = attempt['body'].replace(key, '[REDACTED]')
            attempt['headers'] = core.redact(attempt['headers'], key)
        ref_id = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4)
        captured = dt.datetime.now(dt.timezone.utc).isoformat()
        folder = self.discovery_dir/self.endpoint_key(base_url)
        result = dict(ref_id=ref_id, endpoint=core.endpoint(base_url), base_url=base_url,
                      captured_at=captured, attempts=attempts, models=kept, count=len(kept),
                      note='列表由端点自报，可被改写；它用于生成待测假设，不用于判定模型身份。')
        with self.lock:
            folder.mkdir(exist_ok=True)
            tmp = folder/(ref_id+'.tmp')
            tmp.write_text(core.dumps(result), encoding='utf-8')
            tmp.replace(folder/(ref_id+'.json'))
            (folder/'latest.txt').write_text(ref_id, encoding='utf-8')
        return dict(ref_id=ref_id, captured_at=captured, endpoint=result['endpoint'],
                    models=kept, count=len(kept),
                    attempts=[{k: v for k, v in a.items() if k != 'body'} for a in attempts])

    def load_discovery(self, ref_id):
        """Read a stored probe by id. The folder is derived from the endpoint, so
        the id alone never reaches the filesystem."""
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', str(ref_id)):
            raise ValueError('无效的模型列表引用 ID')
        with self.lock:
            for folder in sorted(self.discovery_dir.iterdir()):
                if not folder.is_dir() or folder.is_symlink():
                    continue
                path = folder/(str(ref_id)+'.json')
                if path.is_file() and not path.is_symlink():
                    return json.loads(path.read_text(encoding='utf-8-sig'))
        raise ValueError('找不到该次模型列表探测记录')

    def attach_discovery(self, out, ref):
        """Copy one stored probe into a run so the run is self-contained."""
        if not ref or not ref.get('ref_id'):
            return
        try:
            stored = self.load_discovery(ref['ref_id'])
        except (ValueError, OSError):
            return
        (out/'models.json').write_text(core.dumps(stored), encoding='utf-8')

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
                    declared_model=config['model'],prompt_sha256=core.digest(case['prompt']),
                    recorded_at=dt.datetime.now(dt.timezone.utc).isoformat(),request=payload,
                    request_sha256=core.digest(core.dumps(payload)),raw_file=raw_file,
                    validation_pass=core.check(case,row))
                row = safe_row(row,key)
                with self.lock:
                    with (out/'results.jsonl').open('a', encoding='utf-8') as f:
                        f.write(core.dumps(row)+'\n')
                    rows.append(row)
                    self.state['completed'] = len(rows)
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
                    f.write('\n完整响应的延迟中位数不包含失败调用。\n')
                    # The advertised list is context for every other signal: an
                    # unlisted declared model changes how the run should be read.
                    ref = config.get('models_ref')
                    if ref:
                        verdict = ('未出现在该端点自报的列表中'
                                   if ref['match'].get('matched') is False else
                                   '出现在该端点自报的列表中'
                                   if ref['match'].get('matched') else '未能取得该端点的模型列表')
                        f.write('\n## 模型列表核对\n\n')
                        f.write(f'- 自报列表（{ref["count"]} 项，来源 {core.md(ref["url"] or "—")}，'
                                f'采集于 {core.md(ref["captured_at"] or "—")}）：请求的模型 ID {verdict}。\n')
                        if ref['match'].get('loose'):
                            f.write('- 命中方式是去前缀匹配，列表用的是供应商限定名。\n')
                        f.write('- 列表由端点自报，可被改写。它只用于生成待测假设，不能证明底层模型身份。\n')
                config.update(status=status,message=message,completed_requests=len(rows))
                config['tokref_snapshot'] = self.library_snapshot()
                with (out/'report.md').open('a',encoding='utf-8') as f:
                    f.write(self.tokref_lines(rows))
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

    def load(self, run_id, full=True):
        with self.lock:
            out = self.resolve(run_id)
            manifest = json.loads((out/'manifest.json').read_text(encoding='utf-8-sig'))
            rows = []
            if (out/'results.jsonl').exists():
                for line in (out/'results.jsonl').read_text(encoding='utf-8-sig').splitlines():
                    if line.strip():
                        rows.append(json.loads(line))
            if not full:
                return dict(manifest=manifest,rows=rows,summary=summarize(rows))
            report = (out/'report.md').read_text(encoding='utf-8') if (out/'report.md').exists() else ''
            refreshed = self.refresh_report(report, rows, manifest)
            if refreshed is not None:
                report = refreshed
            models = None
            if (out/'models.json').is_file() and not (out/'models.json').is_symlink():
                stored = json.loads((out/'models.json').read_text(encoding='utf-8-sig'))
                # The UI only needs the ids and the route they came from; the raw
                # bodies stay on disk for anyone auditing the evidence.
                models = dict(models=stored.get('models', []), count=stored.get('count', 0),
                              captured_at=stored.get('captured_at'),
                              url=(stored.get('attempts') or [{}])[0].get('url'),
                              attempts=[{k: v for k, v in a.items() if k != 'body'}
                                        for a in stored.get('attempts', [])])
            # Matched against the current library, so a reference added later
            # applies to older runs too.
            return dict(manifest=manifest,rows=rows,summary=summarize(rows),report=report,
                        signals=fp.signals(rows),models=models,
                        tokref=fp.tokenizer_matches(rows,self.references(),probe_hashes()),
                        tokref_snapshot=self.library_snapshot(manifest.get('tokref_snapshot')))

    def history(self):
        history = []
        for out in sorted(self.data_dir.iterdir(), reverse=True):
            if out.name.startswith('_') or out.is_symlink() or not out.is_dir():
                continue  # Underscore folders hold non-run data such as discoveries.
            if (out/'manifest.json').exists():
                try:
                    item = self.load(out.name, full=False)
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
            if path == '/api/models':
                return self.send(200, lab.discover({'base_url': query.get('base_url', [''])[0],
                                                    'api_key': self.headers.get('X-Provider-Key', ''),
                                                    'timeout': float(query.get('timeout', ['15'])[0])}))
            if path == '/api/references':
                return self.send(200, lab.references())
            if path == '/api/meta':
                return self.send(200,dict(version=core.VERSION,cases=core.suite(800),presets=PRESETS,data_dir=str(lab.data_dir)))
            if path == '/api/state':
                return self.send(200,lab.snapshot())
            if path == '/api/history':
                return self.send(200,lab.history())
            if path == '/api/run':
                return self.send(200,lab.load(query.get('id',[''])[0]))
            if path == '/api/discovery':
                # Strips the stored bodies: they can be large and are already on
                # disk next to the run for anyone who wants the full evidence.
                stored = lab.load_discovery(query.get('ref_id',[''])[0])
                return self.send(200,{k: v for k, v in stored.items() if k != 'attempts'}
                                 | {'attempt_refs': [a['url'] for a in stored.get('attempts', [])]})
            if path == '/api/export':
                run_id = query.get('id',[''])[0]
                out = lab.resolve(run_id)
                if lab.snapshot()['run_id'] == run_id and lab.snapshot()['status'] in ('running','stopping'):
                    raise ValueError('请等待任务结束后再导出')
                # The exported report is refreshed the same way the detail view
                # is, so a shared ZIP cannot disagree with what is on screen.
                item = lab.load(run_id)
                report = item['report'].encode('utf-8')
                buf = io.BytesIO()
                with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as archive:
                    for f in out.rglob('*'):
                        if f.is_file() and not f.is_symlink() and f.suffix != '.tmp':
                            if f.name == 'report.md':
                                archive.writestr('report.md', report)
                            else:
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
            elif path == '/api/reference':
                if self.server.lab.snapshot()['run_id'] == data.get('run_id') and \
                        self.server.lab.snapshot()['status'] in ('running','stopping'):
                    raise ValueError('请等待检测结束后再设为参照')
                result = self.server.lab.add_reference(data)
            elif path == '/api/reference/delete':
                result = self.server.lab.delete_reference(str(data.get('id', '')))
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
