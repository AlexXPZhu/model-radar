#!/usr/bin/env python3
"""OpenAI-compatible behavioral fingerprint collector. Python 3.10+, stdlib only."""
import argparse
import collections
import csv
import datetime as dt
import getpass
import json
import os
from pathlib import Path
import random
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import fingerprint as fp

VERSION = '2.1.0'
SCHEMA = {'type': 'json_schema', 'json_schema': {'name': 'probe', 'strict': True,
    'schema': {'type': 'object', 'properties': {'x': {'type': 'integer'}},
               'required': ['x'], 'additionalProperties': False}}}

# Tokenizer probes share one wrapper. Comparing each probe against the empty
# tokenizer_base cancels the chat template and any hidden system prompt a relay
# injects, leaving only how the payload itself was sliced. tokenizer_0/1 keep
# their 2.0 text so older runs still line up with references.
TOKENIZER_WRAPPER = 'Reply with exactly OK. Data:\n'
TOKENIZER_PAYLOADS = {
    'tokenizer_base': '',
    'tokenizer_0': 'Hello, 世界! 👨‍💻🚀\nantidisestablishmentarianism\n道德道德道德',
    'tokenizer_1': 'a'*64 + '\n1234567890'*8 + '\n你好世界'*16,
    # Digit grouping separates 3-digit BPE vocabularies from per-digit ones.
    'tokenizer_2': '1234567890 '*32 + '\n' + '```python\nx = 1\n```',
    'tokenizer_3': '🎉'*48 + '\n' + '안녕하세요'*12 + '\n' + 'ЁЖЗИЙ'*16,
    # Natural Chinese prose: vocabularies trained on Chinese compress it most.
    'tokenizer_4': ('清晨的薄雾笼罩着古老的石桥，河面上偶尔传来渔夫低沉的号子。'
                    '镇上的茶馆刚刚开门，掌柜一边擦拭着桌椅，一边和熟客闲谈今年的收成与天气。'
                    '远处的山峦在阳光下渐渐显出轮廓，仿佛一幅尚未完成的水墨画。'),
    # Indentation runs and a tab: whitespace merging differs between vocabularies.
    'tokenizer_5': ('def merge(a, b):\n    out = []\n    while a and b:\n        if a[0] <= b[0]:\n'
                    '            out.append(a.pop(0))\n        else:\n            out.append(b.pop(0))\n'
                    '\treturn out + a + b\n'),
}

# Re-exported so existing callers of core.dumps/core.digest keep working.
dumps = fp.dumps
digest = fp.digest
redact = fp.redact
md = fp.md


def validate_key(key, model):
    key = key.strip()
    if not key:
        raise ValueError('API key is empty.')
    if key.lower().startswith('bearer '):
        raise ValueError('Paste only the API key, without the Bearer prefix.')
    if key.startswith(('"', "'")) or key.endswith(('"', "'")):
        raise ValueError('Paste the API key without surrounding quotes.')
    if any(ord(c) < 33 or ord(c) > 126 for c in key):
        raise ValueError('API key contains whitespace, control or non-ASCII characters. Copy it again.')
    if key == model:
        raise ValueError('API key and model are identical. Enter the model ID separately from the secret key.')
    return key


def suite(long_lines):
    """Fixed corpus; no LLM judge and no execution of returned code."""
    cases = []
    def add(name, category, prompt, params=None, expected=None):
        cases.append(dict(id=name, category=category, prompt=prompt,
                          params=params or {}, expected=expected))
    add('baseline', 'control', 'Reply with exactly: hello', expected='hello')
    add('instruction', 'instruction-following',
        'Return exactly three lines, no spaces or explanation:\nred\ngreen\nblue', expected='red\ngreen\nblue')
    add('math', 'math', 'Compute 12347 * 9876. Output only the integer.', expected='121938972')
    add('logic', 'math', 'How many integers from 1 through 100 inclusive are divisible by 3 or 5? Output only the integer.', expected='47')
    add('code_trace', 'code', 'Python 3: a=[1,2]; b=a; a += [3]; print(len(b)). Output only the printed integer.', expected='3')
    add('code_generation', 'code', 'Write a Python function stable_unique(xs) that removes duplicates preserving order, supports unhashable elements, and does not mutate xs. Return code only.')
    add('chinese', 'chinese', '把“尽管下雨，他还是按时到了。”改写成使用“虽然……但是……”的一句话。只输出改写后的句子。')
    add('chinese_order', 'chinese', '将以下词语按给定顺序倒序输出，用中文逗号分隔，不加标点或解释：山，水，云，月', expected='月，云，水，山')
    add('english', 'writing', 'Describe a silent train station in exactly two sentences, without using the words quiet, empty, or lonely.')
    for name, text in TOKENIZER_PAYLOADS.items():
        add(name, 'usage', TOKENIZER_WRAPPER+text, expected='OK')
    lines = [f'row-{i:05d}: ordinary archive record.' for i in range(long_lines)]
    for pos, val in zip([0, long_lines//2, long_lines-1], ['amber-17','jade-42','violet-93']):
        lines[pos] = f'row-{pos:05d}: SECRET={val}'
    add('long_text', 'long-context', 'Read the archive. Return the three SECRET values in order, separated by commas, with no spaces.\n'+'\n'.join(lines), expected='amber-17,jade-42,violet-93')
    for name, params in [('temperature', {'temperature': 0}), ('top_p', {'top_p': 1}),
                         ('seed', {'seed': 12345}), ('logprobs', {'logprobs': True}),
                         ('top_logprobs', {'logprobs': True, 'top_logprobs': 3}),
                         ('max_tokens', {'max_tokens': 32}),
                         ('max_completion_tokens', {'max_completion_tokens': 32})]:
        add(name, 'compatibility', 'Reply with exactly: hello', params, 'hello')
    add('stop', 'compatibility', 'Output exactly ALPHA|OMEGA', {'stop': ['|']}, 'ALPHA')
    add('json_object', 'compatibility', 'Return JSON only: an object with integer x equal to 7.', {'response_format': {'type':'json_object'}})
    add('json_schema', 'compatibility', 'Return JSON only: an object with integer x equal to 7.', {'response_format': SCHEMA})
    add('stream', 'compatibility', 'Count from 1 to 10, separated by spaces.', {'stream': True})
    add('stream_usage', 'compatibility', 'Count from 1 to 10, separated by spaces.', {'stream': True, 'stream_options': {'include_usage': True}})
    return cases


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def endpoint(base):
    u = urllib.parse.urlsplit(base.strip())
    if u.scheme not in ('https', 'http') or not u.hostname or u.username or u.password or u.query or u.fragment:
        raise ValueError('base_url must be an http(s) URL without credentials, query or fragment')
    if u.scheme == 'http' and u.hostname not in ('localhost', '127.0.0.1', '::1'):
        raise ValueError('Use HTTPS for non-local endpoints')
    # Preserve custom API prefixes; never guess a missing /v1.
    return base.rstrip('/') if u.path.rstrip('/').endswith('/chat/completions') else base.rstrip('/')+'/chat/completions'


def collect(url, key, payload, timeout):
    start = time.perf_counter()
    r = dict(http_status=None, headers=[], model=None, system_fingerprint=None,
             usage=None, text='', ttft_s=None, first_event_s=None, headers_s=None,
             total_s=None, stream_requested=bool(payload.get('stream')), stream_observed=False,
             done=False, finish_reasons=[], events=[], parse_errors=[], error=None,
             logprobs_present=False, logprobs=None, response_ids=[])
    raw = bytearray()
    def consume(obj, elapsed):
        if not isinstance(obj, dict):
            r['parse_errors'].append('JSON response/event is not an object')
            return
        if obj.get('error') is not None:
            r['error'] = dumps(obj['error'])
        if isinstance(obj.get('id'), str) and obj['id'] not in r['response_ids']:
            r['response_ids'].append(obj['id'])
        for field in ('model', 'system_fingerprint', 'usage'):
            if obj.get(field) is not None:
                r[field] = obj[field]
        for choice in obj.get('choices') or []:
            if choice.get('index', 0) != 0:
                continue
            msg = choice.get('delta') or choice.get('message') or {}
            content = msg.get('content')
            if isinstance(content, str) and content:
                if r['stream_observed'] and r['ttft_s'] is None:
                    r['ttft_s'] = elapsed
                r['text'] += content
            if choice.get('finish_reason'):
                r['finish_reasons'].append(choice['finish_reason'])
            if choice.get('logprobs') is not None:
                r['logprobs_present'] = True
                # The token slicing is the strongest tokenizer signal available.
                # Keep the normalized description in the record; the full payload
                # with its probabilities stays in the raw body file.
                if r['logprobs'] is None:
                    r['logprobs'] = fp.logprobs_notes(choice['logprobs'])
    try:
        req = urllib.request.Request(url, data=dumps(payload).encode(), headers={
            'Authorization': 'Bearer '+key, 'Content-Type': 'application/json',
            'Accept': 'text/event-stream' if payload.get('stream') else 'application/json',
            'Accept-Encoding': 'identity', 'User-Agent': 'behavior-fingerprint/'+VERSION})
        try:
            response = urllib.request.build_opener(NoRedirect()).open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            response = e
        with response as resp:
            r['headers_s'] = time.perf_counter()-start
            r['http_status'] = resp.code
            r['headers'] = list(resp.headers.items())
            r['stream_observed'] = 'text/event-stream' in resp.headers.get('Content-Type', '').lower()
            if r['stream_observed']:
                data = []
                def dispatch():
                    if not data:
                        return
                    s = '\n'.join(data)
                    data.clear()
                    elapsed = time.perf_counter()-start
                    if r['first_event_s'] is None:
                        r['first_event_s'] = elapsed
                    r['events'].append({'elapsed_s': elapsed, 'data': s})
                    if s.strip() == '[DONE]':
                        r['done'] = True
                        return
                    try:
                        consume(json.loads(s), elapsed)
                    except (ValueError, TypeError, AttributeError) as e:
                        r['parse_errors'].append(str(e))
                while True:
                    line = resp.readline()
                    if not line:
                        dispatch()
                        break
                    raw.extend(line)
                    s = line.decode('utf-8', errors='replace').rstrip('\r\n')
                    if not s:
                        dispatch()
                        if r['done']:
                            break
                    elif s.startswith('data:'):
                        data.append(s[5:].removeprefix(' '))
            else:
                while True:
                    block = resp.read(65536)
                    if not block:
                        break
                    raw.extend(block)
                try:
                    consume(json.loads(raw), time.perf_counter()-start)
                except (ValueError, TypeError, AttributeError) as e:
                    r['parse_errors'].append(str(e))
    except KeyboardInterrupt:
        r['error'] = 'Interrupted by user'
        r['interrupted'] = True
    except Exception as e:
        r['error'] = type(e).__name__+': '+str(e)
    r['total_s'] = time.perf_counter()-start
    r['http_ok'] = r['http_status'] is not None and 200 <= r['http_status'] < 300
    r['complete'] = (r['http_ok'] and not r['error'] and not r['parse_errors']
                     and bool(r['finish_reasons']) and (not r['stream_observed'] or r['done']))
    r['output_sha256'] = digest(r['text'])
    return r, bytes(raw)


def check(case, r):
    if not r['complete']:
        return None
    if case['id'] in ('json_schema', 'json_object'):
        try:
            obj = json.loads(r['text'])
            return isinstance(obj, dict) and set(obj) == {'x'} and type(obj['x']) is int and obj['x'] == 7
        except ValueError:
            return False
    if case['expected'] is not None:
        return r['text'] == case['expected']
    return None


def reports(out, rows, planned):
    fields = ['run_id','case_id','category','repeat','http_status','complete','model',
              'system_fingerprint','usage','ttft_s','total_s','validation_pass',
              'output_sha256','error','raw_file','request_sha256']
    with (out/'summary.csv').open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            row = {k: dumps(r.get(k)) if isinstance(r.get(k), (dict,list)) else r.get(k) for k in fields}
            for k,v in row.items():
                if isinstance(v, str) and v.startswith(('=', '+', '-', '@', '\t', '\r')):
                    row[k] = "'"+v
            w.writerow(row)
    grouped = collections.defaultdict(list)
    for r in rows:
        grouped[r['case_id']].append(r)
    lines = ['# 中转站模型行为指纹报告', '',
        '**这是行为指纹/侧信道分析，不能 100% 确定底层模型，也不输出模型身份概率。**', '',
        f'已记录 {len(rows)} / {planned} 次请求；HTTP 2xx {sum(r["http_ok"] for r in rows)} 次；完整响应 {sum(r["complete"] for r in rows)} 次。',
        'model、system_fingerprint、usage 和响应头均由服务端提供，可被改写。缺失字段不等于伪造。', '',
        '| 测试 | 完整/调用 | 自动检查通过/可检查 | 不同文本数/完整响应 | 总延迟中位数(s) | TTFT中位数(s) |',
        '|---|---:|---:|---:|---:|---:|']
    for name, group in grouped.items():
        good = [r for r in group if r['complete']]
        checked = [r for r in good if r['validation_pass'] is not None]
        ttft = [r['ttft_s'] for r in good if r['ttft_s'] is not None]
        times = [r['total_s'] for r in group if type(r.get('total_s')) in (float,int)]
        delay = f'{statistics.median(times):.3f}' if times else '—'
        lines.append(f'| {md(name)} | {len(good)}/{len(group)} | {sum(r["validation_pass"] for r in checked)}/{len(checked)} | {len(set(r["output_sha256"] for r in good))}/{len(good)} | {delay} | {f"{statistics.median(ttft):.3f}" if ttft else "—"} |')
    lines += ['', '## 参数兼容性观察', '', '| 参数探针 | HTTP状态 | 观察（不代表参数确实生效） |', '|---|---|---|']
    for name, group in grouped.items():
        if group[0]['category'] != 'compatibility':
            continue
        notes = []
        for r in group:
            obs = '响应完整' if r['complete'] else '响应失败或不完整，检查原始记录'
            if r['validation_pass'] is not None:
                obs += '；输出检查='+str(r['validation_pass'])
            if name in ('logprobs','top_logprobs'):
                obs += '；logprobs字段='+str(r['logprobs_present'])
            if name.startswith('stream'):
                obs += '；SSE='+str(r['stream_observed'])+'；usage='+str(r['usage'] is not None)
            notes.append(obs)
        lines.append(f'| {md(name)} | {md(sorted(set(str(r["http_status"]) for r in group)))} | {md(" / ".join(dict.fromkeys(notes)))} |')
    lines += ['', '## 元数据与解释', '',
        '- 返回 model：'+md(sorted(set(str(r['model']) for r in rows))),
        '- 返回 system_fingerprint：'+md(sorted(set(str(r['system_fingerprint']) for r in rows))),
        '- 不同文本数使用原始输出 SHA-256；失败调用不计入稳定性。只有一次完整响应时无法评价重复稳定性。',
        '- temperature/seed 被接受不等于生效；JSON/stop 输出符合要求也可能来自模型自然遵循提示。',
        '- 401/403、429、5xx、网络异常不能判定参数不兼容；400/422 也需结合错误正文和 baseline 判断。',
        '- TTFT 从发起请求到首个非空 content 增量，仅是客户端观测值，包含网络与代理缓冲；role、推理字段和空事件不计入。',
        '- 总延迟包含连接与读取；流式读至 [DONE] 或 EOF。截断、拒答、length 结束请结合 finish_reasons 检查。',
        '- 固定答案采用精确字符检查，前后空白也会判为不通过。自动检查只覆盖固定答案与本工具的简单 schema；代码生成不执行，写作与改写需人工阅读。',
        '- 对照官方候选端点使用相同 corpus_sha256、参数、长度和重复数。缓存、系统提示、负载、版本与采样均会混淆结果。',
        '- 更相似的输出只能支持行为相似；没有可信上游证据时不应据此宣布真实模型身份。']
    lines += signal_lines(rows)
    lines.append('')
    (out/'report.md').write_text('\n'.join(lines), encoding='utf-8')


def signal_lines(rows):
    """Markdown for the side-channel signals that the rows already contain."""
    data = fp.signals(rows)
    agree = data['agreement']
    lines = ['', '## 侧信道信号（来自已采集记录）', '',
        '这些字段全部来自本次已保存的响应，不增加任何 API 调用。它们描述链路特征，不能单独判定模型身份。', '',
        '| 信号 | 观察 |', '|---|---|']
    for label in ('model', 'system_fingerprint', 'id_prefixes'):
        point = agree.get(label) or {}
        lines.append(f'| 响应字段 {md(label)} | 取值 {md(point.get("values") or "—")}；'
                     f'{"本次运行内出现变化" if point.get("mixed") else "本次运行内一致"} |')
    declared = agree.get('declared_model')
    if declared:
        lines.append(f'| 请求的模型 ID | {md(declared["values"])}；'
                     + ('与响应返回的 model **不一致**' if declared['returned_differs']
                        else '与响应返回的 model 一致') + ' |')
    head = data['headers']
    if head['collected']:
        lines.append(f'| 响应头（{head["collected"]}/{head["total"]} 次记录） | '
                     f'观测到 {md([n["name"] for n in head["notes"]])}；'
                     f'未见 {md(head["absent"])}；'
                     + (f'限流/追踪类：{md(head["present"])}' if head['present'] else '未见限流或追踪类头部') + ' |')
    for item in data['tokenizer']:
        lines.append(f'| 分词探针 {md(item["case_id"])} | 输入计数 {md(item.get("prompt_tokens"))}'
                     + ('；' + md(item['note']) if item.get('note') else
                        '；' + ('重复一致' if item.get('stable') else '重复间不一致，需核对')) + ' |')
    for item in data['logprobs']:
        lines.append(f'| logprobs 分词 {md(item["case_id"])} | 切分出 {md(item["token_counts"])} 个 token；'
                     f'{item["distinct_tokenizations"]} 种切分；样例 {md(item["sample"])} |')
    for stream in data['streams']:
        if stream.get('gaps'):
            lines.append(f'| 流式节奏 {md(stream["case_id"])} #{stream.get("repeat")} | '
                         f'{stream["profile"]}；块间中位 {stream["gap_p50"]}s，抖动 {stream["gap_stdev"]}，'
                         f'同批到达占比 {stream["simultaneous_ratio"]} |')
    usage = data.get('usage_keys')
    if usage:
        lines.append(f'| usage 字段 | {md(usage["keys"])}；缓存类 {md(usage["cached"] or "无")}；'
                     f'推理类 {md(usage["reasoning"] or "无")} |')
    lines += ['', '- 响应 ID 前缀与 system_fingerprint 由服务端生成，可被代理转发或改写；相同前缀只说明链路相似。',
        '- 流式节奏反映缓冲与排队：整段一起到达通常是缓冲，而不是模型生成速度。',
        '- usage 中缓存/推理字段缺失，可能是上游未产生，也可能是适配层丢弃，需结合对照端点判断。', '']
    return lines


def model_urls(base):
    """Candidate list endpoints, most likely first. A custom prefix is honoured first."""
    text = base.strip().rstrip('/')
    if text.lower().endswith('/chat/completions'):
        text = text[:-len('/chat/completions')].rstrip('/')
    urls = [text + '/models']
    if text.endswith('/v1'):
        # Some relays only expose the prefix-free path; others nest it twice.
        urls.append(text[:-len('/v1')] + '/models')
        urls.append(text + '/v1/models')
    urls.append(text + '/api/tags')
    if not text.endswith('/v1'):
        urls.append(text + '/v1/models')
    return list(dict.fromkeys(urls))


def _model_id(item):
    """Accept the OpenAI shape and the looser shapes relays and Ollama return."""
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        for field in ('id', 'name', 'model'):
            if isinstance(item.get(field), str):
                return item[field]
    return None


def parse_model_list(body):
    """Extract ids plus the container shape that carried them.

    A relay's list is self-reported metadata, exactly like the model field on a
    chat response. It names what to test; it never identifies a backend.
    """
    try:
        data = json.loads(body.decode('utf-8', errors='replace'))
    except (ValueError, AttributeError):
        return [], 'unparsed'
    shape, items = None, None
    if isinstance(data, list):
        shape, items = 'array', data
    elif isinstance(data, dict):
        for key in ('data', 'models', 'model'):
            if isinstance(data.get(key), list):
                shape, items = 'object.' + key, data[key]
                break
    if items is None:
        return [], shape or 'unknown'
    seen, ids = set(), []
    for item in items:
        value = _model_id(item)
        if value and value not in seen and len(value) <= 200:
            seen.add(value)
            ids.append(value)
    return ids, shape


def list_models(base, key, timeout):
    """Probe candidate list endpoints and return every attempt, including failures.

    Bodies are returned raw and unbounded: the caller decides what to persist.
    """
    attempts = []
    for url in model_urls(base):
        start = time.perf_counter()
        status, headers, body, error = None, [], b'', None
        try:
            req = urllib.request.Request(url, headers={
                'Authorization': 'Bearer '+key, 'Accept': 'application/json',
                'Accept-Encoding': 'identity', 'User-Agent': 'behavior-fingerprint/'+VERSION})
            try:
                response = urllib.request.build_opener(NoRedirect()).open(req, timeout=timeout)
            except urllib.error.HTTPError as e:
                response = e
            with response as resp:
                status = resp.code
                headers = list(resp.headers.items())
                body = resp.read(4_000_000)
        except Exception as e:
            error = type(e).__name__+': '+str(e)
        ids, shape = parse_model_list(body) if body else ([], 'empty')
        attempts.append(dict(url=url, http_status=status, shape=shape, count=len(ids),
                             models=ids, headers=list(fp.safe_headers(headers)),
                             body=body.decode('utf-8', errors='replace'), error=error,
                             elapsed_s=round(time.perf_counter()-start, 3)))
        if ids:
            break
    return attempts


def match_model(model, names):
    """Compare the requested id against the advertised list, tolerating prefixes.

    OpenRouter advertises vendor/model while callers often type the bare name, so
    a vendor-qualified advertisement counts as present and is reported as loose.
    unrelated_name must never match: only a proper path prefix does.
    """
    if not names:
        return dict(matched=None, loose=False)
    if model in names:
        return dict(matched=True, loose=False)
    loose = any(m.endswith('/'+model) or (model.endswith('/'+m) and m)
                for m in names if isinstance(m, str))
    return dict(matched=bool(loose), loose=bool(loose))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base-url', default=os.getenv('OPENAI_BASE_URL'))
    p.add_argument('--api-key', default=os.getenv('OPENAI_API_KEY'), help='Prefer environment variable or hidden prompt')
    p.add_argument('--prompt-key', action='store_true', help='Ignore CLI/environment API key and prompt for a fresh key')
    p.add_argument('--model', default=os.getenv('OPENAI_MODEL'))
    p.add_argument('--repeats', type=int, default=3)
    p.add_argument('--long-lines', type=int, default=800)
    p.add_argument('--timeout', type=float, default=90, help='Socket operation timeout, not a total deadline')
    p.add_argument('--interval', type=float, default=0.5)
    p.add_argument('--out', default='fingerprint_runs')
    p.add_argument('--only', help='Comma-separated case IDs')
    p.add_argument('--shuffle-seed', type=int, default=20260929)
    p.add_argument('--list', action='store_true')
    p.add_argument('--dry-run', action='store_true', help='Print request count and corpus hash; no API call')
    a = p.parse_args()
    if a.repeats < 1 or a.long_lines < 3 or a.timeout <= 0 or a.interval < 0:
        p.error('repeats >= 1, long-lines >= 3, timeout > 0, interval >= 0 required')
    cases = suite(a.long_lines)
    if a.only:
        ids = set(a.only.split(','))
        unknown = ids - {c['id'] for c in cases}
        if unknown:
            p.error('Unknown case IDs: '+','.join(sorted(unknown)))
        cases = [c for c in cases if c['id'] in ids]
    if a.list:
        for c in cases:
            print(c['id']+'\t'+c['category'])
        return 0
    corpus_hash = digest(dumps(cases))
    count = len(cases)*a.repeats
    print(f'{len(cases)} cases x {a.repeats} repeats = {count} requests. Corpus: {corpus_hash}')
    if a.dry_run:
        return 0
    base = a.base_url or input('base_url (include API prefix, e.g. https://host/v1): ').strip()
    try:
        url = endpoint(base.strip())
    except ValueError as e:
        p.error(str(e))
    model = a.model or input('model: ').strip()
    fresh_key = a.prompt_key or not a.api_key
    key = getpass.getpass('api_key (hidden): ') if fresh_key else a.api_key
    try:
        key = validate_key(key, model)
    except ValueError as e:
        p.error(str(e))
    if not key or not model:
        p.error('api_key and model must be nonempty')
    run_id = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
    out = Path(a.out)/run_id
    (out/'raw').mkdir(parents=True, exist_ok=False)
    config = dict(version=VERSION, run_id=run_id, endpoint=url, model=model,
                  repeats=a.repeats, long_lines=a.long_lines, timeout=a.timeout,
                  interval=a.interval, shuffle_seed=a.shuffle_seed, corpus_sha256=corpus_hash,
                  planned_requests=count, python=sys.version, cases=cases)
    (out/'manifest.json').write_text(dumps(redact(config, key)), encoding='utf-8')
    schedule = [(c, i+1) for i in range(a.repeats) for c in cases]
    random.Random(a.shuffle_seed).shuffle(schedule)
    rows = []
    print('Output: '+str(out.resolve()))
    print('API key source: '+('fresh hidden prompt' if fresh_key else 'CLI option or OPENAI_API_KEY environment variable'))
    print('Requests may incur provider charges. No automatic retries or parameter fallback.')
    try:
        for n, (case, repeat) in enumerate(schedule, 1):
            payload = dict(model=model, messages=[{'role':'user','content':case['prompt']}], **case['params'])
            r, raw = collect(url, key, payload, a.timeout)
            raw_name = f'raw/{n:04d}_{case["id"]}_{repeat}.body'
            # Preserve response body bytes except exact API-key occurrences.
            (out/raw_name).write_bytes(raw.replace(key.encode(), b'[REDACTED]'))
            r.update(run_id=run_id, case_id=case['id'], category=case['category'], repeat=repeat,
                     declared_model=model, prompt_sha256=digest(case['prompt']),
                     recorded_at=dt.datetime.now(dt.timezone.utc).isoformat(),
                     request=payload, request_sha256=digest(dumps(payload)), raw_file=raw_name,
                     validation_pass=check(case, r))
            r['headers'] = fp.safe_headers(r['headers'])
            r = redact(r, key)
            with (out/'results.jsonl').open('a', encoding='utf-8') as f:
                f.write(dumps(r)+'\n')
                f.flush()
            rows.append(r)
            reports(out, rows, count)
            print(f'[{n}/{count}] {case["id"]} #{repeat}: HTTP {r["http_status"]}, complete={r["complete"]}, {r["total_s"]:.2f}s')
            if r.get('interrupted') or r['http_status'] in (401,403):
                print('Stopped: interrupt or authentication/permission failure.')
                if r['http_status'] == 401:
                    print('HTTP 401: the responding server rejected authentication; this does not prove which layer rejected it.')
                    print('Try --prompt-key to bypass saved environment credentials. If it still fails, compare with the provider example or ask support to trace the request ID in results.jsonl.')
                break
            if n < count:
                time.sleep(a.interval)
    except KeyboardInterrupt:
        print('\nInterrupted; completed records retained.')
    finally:
        reports(out, rows, count)
    print('Report: '+str((out/'report.md').resolve()))
    return 0 if len(rows) == count and all(r['complete'] for r in rows) else 2


if __name__ == '__main__':
    sys.exit(main())
