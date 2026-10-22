#!/usr/bin/env python3
"""Side-channel extraction over records that were already collected. Stdlib only.

This module never talks to the network. It turns one run's rows into reproducible
signals, and every signal carries provenance: an observation, not a verdict.
"""
import collections
import datetime as dt
import hashlib
import json
import re
import statistics

# Known response-id prefixes, longest first. Used to describe an ID, never to
# assign an issuer. A proxy can relay or rewrite ids freely. Every entry ends in
# a separator: a bare hex fragment such as "019" would collide with ordinary ids
# and say nothing.
ID_PREFIXES = [
    'chatcmpl-', 'cmpl-', 'msg_', 'msg-', 'gen-', 'resp_', 'resp-',
    'request-', 'infer-', 'run-', 'id-',
]

# Secure by name: the exact set below is always redacted, and the patterns catch
# names like x-session-id. The patterns are anchored on hyphens so that a header
# such as x-tokenizer-version stays visible -- it carries no credential, and it
# is exactly the kind of side channel this tool exists to read.
SENSITIVE_HEADER_EXACT = {
    'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'set-cookie2',
    'api-key', 'apikey', 'x-api-key', 'x-goog-api-key', 'x-api-token',
    'x-auth-token', 'x-access-token', 'x-session-token', 'x-csrf-token',
    'x-xsrf-token', 'x-amz-security-token', 'x-amz-credential', 'x-amz-signature',
}
SENSITIVE_HEADER_PATTERNS = tuple(re.compile(p) for p in (
    r'.*[-_]token(s)?([-_].*)?$', r'.*[-_]secret(s)?([-_].*)?$',
    r'.*[-_]session[-_]?(id|key|token)?$', r'.*[-_]credential(s)?$',
    r'^(auth|authentication|authorize)[-_].*', r'^.*[-_]password$',
))
# Rate-limit accounting is a side channel worth reading, so a name that only
# counts tokens is not treated as a credential.
HEADER_COUNTER = re.compile(r'^(x-)?ratelimit-[a-z0-9-]+$|^(x-)?rate-limit-[a-z0-9-]+$')

INTERESTING_HEADERS = ('x-request-id', 'x-ratelimit-remaining-requests',
                       'x-ratelimit-remaining-tokens', 'x-ratelimit-limit-requests',
                       'retry-after', 'cf-ray', 'x-served-by', 'x-upstream')


def dumps(x):
    return json.dumps(x, ensure_ascii=False, sort_keys=True)


def digest(x):
    return hashlib.sha256(x.encode('utf-8')).hexdigest()


def median(values):
    return round(statistics.median(values), 3) if values else None


def redact(x, key):
    if isinstance(x, str):
        return x.replace(key, '[REDACTED]') if key else x
    if isinstance(x, list):
        return [redact(v, key) for v in x]
    if isinstance(x, tuple):
        return [redact(v, key) for v in x]
    if isinstance(x, dict):
        return {k: redact(v, key) for k, v in x.items()}
    return x


def md(x):
    return str(x).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')


def is_sensitive_header(name):
    low = str(name).strip().lower()
    if low in SENSITIVE_HEADER_EXACT:
        return True
    if HEADER_COUNTER.match(low):
        return False
    return any(p.match(low) for p in SENSITIVE_HEADER_PATTERNS)


def safe_headers(headers):
    """Keep response header names and values except credentials."""
    return [(name, '[REDACTED]' if is_sensitive_header(name) else value)
            for name, value in (headers or [])]


def header_notes(headers, api_key=''):
    """Grouped view of headers, plus which expected ones are absent.

    Content-Length and Transfer-Encoding are kept so that a relay turning a
    stream into a buffered response is visible rather than inferred.
    """
    counts = collections.Counter()
    values = {}
    for name, value in headers or []:
        low = str(name).strip().lower()
        counts[low] += 1
        values[low] = value
    notes = [{'name': name, 'count': count, 'value': str(values[name])[:200]}
             for name, count in sorted(counts.items())]
    return dict(
        notes=redact(notes, api_key),
        absent=[n for n in ('content-type', 'date', 'server', 'x-request-id') if n not in counts],
        present=[n for n in INTERESTING_HEADERS if n in counts],
    )


def describe_id(value):
    """Shape of a response id. A shared shape is a lead, not proof."""
    text = str(value)
    prefix = next((p for p in ID_PREFIXES if text.startswith(p)), None)
    suffix = text[len(prefix):] if prefix else text
    kind = 'none'
    if prefix:
        if suffix.isdigit():
            kind = 'prefix+numeric'
        elif suffix and all(c in '0123456789abcdefABCDEF-' for c in suffix):
            kind = 'prefix+hex'
        elif suffix:
            kind = 'prefix+opaque'
    return dict(prefix=prefix, kind=kind, length=len(text), sample=text[:12],
                sha256=digest(text)[:16])


def id_summary(ids):
    return [describe_id(i) for i in ids]


def logprobs_notes(entry):
    """Describe an observed logprobs payload without keeping every float."""
    if not isinstance(entry, dict):
        return None
    content = entry.get('content')
    tokens = [t.get('token') for t in content if isinstance(t, dict)] if isinstance(content, list) else []
    tokens = [t for t in tokens if isinstance(t, str)]
    if not tokens:
        return dict(present=True, tokens=0, first_tokens=[], bytes=0, token_sha256=None)
    joined = ''.join(tokens)
    return dict(present=True, tokens=len(tokens), first_tokens=tokens[:24],
                bytes=len(joined.encode('utf-8')), token_sha256=digest(dumps(tokens))[:16])


def stream_timeline(r):
    """Per-chunk gaps, jitter and within-stream regularity.

    Gaps come from each SSE chunk's own elapsed timestamp, so a line-flushed
    stream shows small gaps and a buffering relay shows batches of zero gaps.
    """
    events = r.get('events') or []
    if len(events) < 3:
        return dict(chunks=len(events))
    times = [e['elapsed_s'] for e in events if isinstance(e.get('elapsed_s'), (int, float))]
    if len(times) < 3:
        return dict(chunks=len(events))
    gaps = [round(b - a, 4) for a, b in zip(times, times[1:])]
    total_chars = sum(len(e.get('data') or '') for e in events)
    span = times[-1] - times[0]
    zeros = sum(1 for g in gaps if g <= 0.001)
    stdev = statistics.pstdev(gaps) if len(gaps) > 1 else None
    return dict(
        chunks=len(events), gaps=len(gaps),
        first_gap_s=gaps[0], gap_p50=median(gaps), gap_max=max(gaps),
        mean_gap_s=round(sum(gaps) / len(gaps), 4),
        gap_stdev=round(stdev, 4) if stdev is not None else None,
        simultaneous=zeros, simultaneous_ratio=round(zeros / len(gaps), 3),
        chars_per_s=round(total_chars / span, 1) if span > 0 else None,
        profile=('单批缓冲' if zeros / len(gaps) > 0.5 else
                 '平稳' if stdev is not None and stdev < 0.05 else '抖动明显'),
        detail=[dict(index=i, gap_s=gap,
                     bytes=len(events[i + 1].get('data') or ''),
                     chars_per_s=round(len(events[i + 1].get('data') or '') / gap, 1) if gap > 0 else None)
                for i, gap in enumerate(gaps)][:40],
    )


def group_rows(rows):
    grouped = collections.defaultdict(list)
    for r in rows:
        grouped[r.get('case_id')].append(r)
    return grouped


def _prompt_tokens(rows):
    return sorted({r['usage']['prompt_tokens'] for r in rows
                   if isinstance(r.get('usage'), dict) and type(r['usage'].get('prompt_tokens')) is int})


def tokenizer_signals(rows):
    """Per-probe input counts plus checks that need no reference.

    Every payload probe is longer than the empty tokenizer_base, so a count at or
    below the base means the counter never read that payload.
    """
    signals = []
    counted = {}
    for name, group in sorted(group_rows(rows).items()):
        if not name.startswith('tokenizer'):
            continue
        counts = _prompt_tokens([r for r in group if r.get('complete')])
        if not counts:
            continue
        counted[name] = counts
        signals.append(dict(case_id=name, prompt_tokens=counts, stable=len(counts) == 1))
    if len(counted) >= 2 and len({tuple(c) for c in counted.values()}) == 1:
        signals.append(dict(case_id='tokenizer_cross', prompt_tokens=next(iter(counted.values())),
            note='不同长度的分词探针得到完全相同的输入计数，与分词器读取正文不一致。'))
    elif 'tokenizer_base' in counted:
        base = max(counted['tokenizer_base'])
        flat = sorted(n for n, c in counted.items() if n != 'tokenizer_base' and min(c) <= base)
        if flat:
            signals.append(dict(case_id='tokenizer_cross', prompt_tokens=counted['tokenizer_base'],
                note=f'{"、".join(flat)} 的输入计数不高于空载探针，计量没有读取这些正文。'))
    return signals


# --- Tokenizer reference matching ----------------------------------------------
# A reference is the probe counts from a run against an endpoint the user trusts.
# Matching compares each probe's count minus tokenizer_base, so the template and
# any injected system prompt cancel out. A shared tokenizer identifies a family
# (gpt-4o and gpt-4o-mini share one), never a specific model size.

MIN_REFERENCE_PROBES = 4   # tokenizer_base plus at least three payloads


def _row_prompt_hash(row, fallback):
    if isinstance(row.get('prompt_sha256'), str):
        return row['prompt_sha256'], False
    request = row.get('request')
    if isinstance(request, dict):
        messages = request.get('messages')
        if isinstance(messages, list) and messages and isinstance(messages[0], dict) \
                and isinstance(messages[0].get('content'), str):
            return digest(messages[0]['content']), False
    # Imported rows carry no request; assume the current corpus text.
    return (fallback or {}).get(row.get('case_id')), True


def tokenizer_vector(rows, fallback=None):
    """Most common input count per tokenizer probe, keyed by case id."""
    out = {}
    for name, group in sorted(group_rows(rows).items()):
        if not str(name).startswith('tokenizer'):
            continue
        good = [r for r in group if r.get('complete') and isinstance(r.get('usage'), dict)
                and type(r['usage'].get('prompt_tokens')) is int]
        if not good:
            continue
        counts = collections.Counter(r['usage']['prompt_tokens'] for r in good)
        prompt_hash, assumed = _row_prompt_hash(good[0], fallback)
        if not prompt_hash:
            continue
        out[name] = dict(prompt_sha256=prompt_hash, prompt_tokens=counts.most_common(1)[0][0],
                         values=sorted(counts), stable=len(counts) == 1, assumed=assumed)
    return out


def compare_tokenizer(observed, probes):
    """Differential comparison of one observation against one reference.

    Returns None when fewer than MIN_REFERENCE_PROBES probes share identical text.
    """
    common = sorted(c for c in observed if c in probes
                    and observed[c]['prompt_sha256'] == probes[c].get('prompt_sha256'))
    if len(common) < MIN_REFERENCE_PROBES:
        return None
    anchor = 'tokenizer_base' if 'tokenizer_base' in common else common[0]
    diffs = []
    for name in common:
        if name == anchor:
            continue
        seen = observed[name]['prompt_tokens'] - observed[anchor]['prompt_tokens']
        ref = probes[name]['prompt_tokens'] - probes[anchor]['prompt_tokens']
        diffs.append(dict(case_id=name, observed=seen, reference=ref, diff=seen - ref))
    max_abs = max(abs(d['diff']) for d in diffs)
    rel = sum(abs(d['diff']) / max(abs(d['reference']), 1) for d in diffs) / len(diffs)
    # One tokenizer slices identical text identically, so only exact equality
    # counts as a match. "near" covers vocab revisions and estimated counts.
    level = 'exact' if max_abs == 0 else 'near' if rel <= 0.03 and max_abs <= 3 else 'different'
    return dict(anchor=anchor, probes=len(common), diffs=diffs, level=level,
                max_abs_diff=max_abs, mean_rel_err=round(rel, 4),
                offset=observed[anchor]['prompt_tokens'] - probes[anchor]['prompt_tokens'],
                anchored_on_base=anchor == 'tokenizer_base',
                unstable=sorted(c for c in common if not observed[c]['stable']))


# unstable ranks first: it is what the reader needs to see before any distance.
LEVEL_RANK = {'unstable': 0, 'exact': 1, 'near': 2, 'different': 3}


def _same_model(declared, model):
    if not declared or not model:
        return False
    return declared == model or declared.endswith('/'+model) or model.endswith('/'+declared)


def tokenizer_matches(rows, references, fallback=None):
    """Rank references by tokenizer distance, and check the declared model.

    No probabilities: the output is the nearest references with their distance,
    plus whether a reference for the declared model itself agrees.
    """
    observed = tokenizer_vector(rows, fallback)
    usable = len(observed) >= MIN_REFERENCE_PROBES
    matches = []
    for ref in references:
        result = compare_tokenizer(observed, ref.get('probes') or {})
        if not result:
            continue
        entry = dict(ref_id=ref.get('id'), label=ref.get('label'), family=ref.get('family'),
                     model=ref.get('model'), source=ref.get('source'), **result)
        # A level read off an unstable probe counts for nothing on its own.
        if entry['unstable']:
            entry['provisional'] = entry['level']
            entry['level'] = 'unstable'
        matches.append(entry)
    matches.sort(key=lambda m: (LEVEL_RANK[m['level']], m['mean_rel_err'], m['max_abs_diff']))
    declared = next((r['declared_model'] for r in rows if isinstance(r.get('declared_model'), str)), None)
    own = [m for m in matches if _same_model(declared, m['model'])]
    check = None
    if own:
        best = own[0]
        # Each probe takes its own mode, so an unstable run yields a vector that
        # no single upstream ever produced. The verdict is withheld rather than
        # reported as a clean match over the top of that.
        unstable = best['unstable']
        check = dict(model=declared, level=best['level'], ref_id=best['ref_id'], label=best['label'],
                     unstable=unstable, provisional=best.get('provisional'),
                     offset=best['offset'] if best['level'] == 'exact' and best['anchored_on_base']
                            else None)
        if best['level'] == 'different':
            nearest = next((m for m in matches if m['level'] != 'different'), None)
            check['nearest'] = dict(label=nearest['label'], family=nearest['family'],
                                    level=nearest['level']) if nearest else None
    return dict(observed=observed, references=len(references), usable=usable,
                matches=matches[:8], declared=check)


def build_reference(rows, manifest, label, family='', note='', fallback=None):
    """Turn a trusted run into a reference entry, or explain why it cannot be one."""
    if manifest.get('status') == 'imported' or str(manifest.get('run_id', '')).startswith('import-'):
        raise ValueError('导入的记录没有可核对的端点来源，不能作为参照')
    if manifest.get('status') not in ('completed', 'stopped'):
        raise ValueError('请等待检测结束后再设为参照')
    vector = tokenizer_vector(rows, fallback)
    if 'tokenizer_base' not in vector:
        raise ValueError('记录缺少 tokenizer_base 探针；请用“分词与计量”方案重新检测')
    if len(vector) < MIN_REFERENCE_PROBES:
        raise ValueError(f'分词探针不足：需要 tokenizer_base 加至少 {MIN_REFERENCE_PROBES-1} 项，当前 {len(vector)} 项')
    unstable = sorted(n for n, v in vector.items() if not v['stable'])
    if unstable:
        raise ValueError('这些探针的重复计数不一致，计量不稳定，不能作为参照：'+'、'.join(unstable))
    base = vector['tokenizer_base']['prompt_tokens']
    flat = sorted(n for n, v in vector.items() if n != 'tokenizer_base' and v['prompt_tokens'] <= base)
    if flat:
        raise ValueError('这些探针的计数不高于空载探针，计量没有读取正文：'+'、'.join(flat))
    label = str(label or '').strip()[:100]
    if not label:
        raise ValueError('请填写参照名称')
    returned = sorted({r['model'] for r in rows if isinstance(r.get('model'), str)})
    endpoint = str(manifest.get('endpoint') or '')
    host = endpoint.split('://', 1)[-1].split('/', 1)[0]
    return dict(
        label=label, family=str(family or '').strip()[:50], note=str(note or '').strip()[:300],
        model=manifest.get('model'), returned_models=returned, endpoint_host=host,
        run_id=manifest.get('run_id'), run_created_at=manifest.get('created_at'),
        version=manifest.get('version'),
        probes={n: dict(prompt_sha256=v['prompt_sha256'], prompt_tokens=v['prompt_tokens'])
                for n, v in vector.items()})


def valid_reference(entry):
    """Shape check for entries read from disk, including the shipped library."""
    if not isinstance(entry, dict) or not isinstance(entry.get('label'), str):
        return False
    probes = entry.get('probes')
    if not isinstance(probes, dict) or not probes:
        return False
    return all(isinstance(k, str) and isinstance(v, dict) and isinstance(v.get('prompt_sha256'), str)
               and type(v.get('prompt_tokens')) is int for k, v in probes.items())


def metadata_values(row, field):
    values = set(v for v in row.get(field+'_values', []) if isinstance(v, str))
    if isinstance(row.get(field), str):
        values.add(row[field])
    # Older saved runs retained SSE events but only normalized the final value.
    for event in row.get('events') or []:
        try:
            obj = json.loads(event['data'])
            if isinstance(obj, dict) and isinstance(obj.get(field), str):
                values.add(obj[field])
        except (ValueError, TypeError, KeyError):
            pass
    return sorted(values)


def agreement(rows):
    """How tightly metadata repeats, including identity changes mid-run.

    Repeated identical requests may legitimately differ, so a disagreement is a
    lead to verify, never a verdict.
    """
    models = [v for r in rows for v in metadata_values(r, 'model')]
    prints = [v for r in rows for v in metadata_values(r, 'system_fingerprint')]
    out = {}
    for label, values in (('model', models), ('system_fingerprint', prints)):
        counter = collections.Counter(values)
        out[label] = dict(distinct=len(counter), values=[v for v, _ in counter.most_common(8)],
                          mixed=len(counter) > 1,
                          within_response_changes=sum(len(metadata_values(r, label)) > 1 for r in rows))
    prefixes = collections.Counter(d['prefix'] for d in id_summary(
        [i for r in rows for i in (r.get('response_ids') or [])]))
    out['id_prefixes'] = dict(distinct=len(prefixes),
                              values=[p or '(无前缀)' for p, _ in prefixes.most_common(8)],
                              mixed=len(prefixes) > 1)
    declared = sorted({r['declared_model'] for r in rows if isinstance(r.get('declared_model'), str)})
    if declared:
        differs = bool(models) and set(models) != set(declared)
        out['declared_model'] = dict(distinct=len(declared), values=declared, mixed=False,
                                     returned_differs=differs,
                                      note=('请求的模型 ID 与响应返回的 model 不一致；可能是别名或代理改写，不能证明模型身份。'
                                           if differs else '本次运行中两者一致。'))
    return out


def logprobs_signals(rows):
    """Tokenizer slicing exposed by real logprobs payloads."""
    out = []
    for name, group in sorted(group_rows(rows).items()):
        if name not in ('logprobs', 'top_logprobs'):
            continue
        by_text = collections.defaultdict(list)
        for r in group:
            if r.get('complete') and isinstance(r.get('logprobs'), dict) and isinstance(r.get('text'), str):
                by_text[digest(r['text'])].append(r['logprobs'])
        for text_hash, notes in by_text.items():
            firsts = collections.Counter(tuple(n.get('first_tokens') or []) for n in notes)
            sample = next(iter(firsts), ())
            out.append(dict(case_id=name, output_sha256=text_hash, probes=len(notes),
                            token_counts=sorted({n['tokens'] for n in notes}),
                            distinct_tokenizations=len(firsts), stable=len(firsts) == 1 if len(notes) > 1 else None,
                            sample=list(sample)[:12],
                            note='仅比较相同输出文本的已保存切分样例；差异是待核实线索，不证明上游数量或模型身份。'
                                 if len(notes) > 1 else '相同输出文本只有一次记录，无法评价重复切分稳定性。'))
    return out


def usage_paths(value, prefix=''):
    for key, child in value.items():
        path = prefix + str(key)
        yield path
        if isinstance(child, dict):
            yield from usage_paths(child, path+'.')


def signals(rows):
    """Everything this run implies about the chain in front of the model."""
    headers = sorted({(k, v) for r in rows if r.get('headers') for k, v in r['headers']})
    note = header_notes(headers)
    usages = [r['usage'] for r in rows if isinstance(r.get('usage'), dict)]
    out = dict(
        agreement=agreement(rows),
        tokenizer=tokenizer_signals(rows),
        logprobs=logprobs_signals(rows),
        headers=dict(notes=note['notes'], absent=note['absent'], present=note['present'],
                     collected=sum(1 for r in rows if r.get('headers')), total=len(rows)),
        streams=[dict(case_id=r.get('case_id'), repeat=r.get('repeat'),
                      **{k: v for k, v in stream_timeline(r).items() if k != 'detail'})
                 for r in rows if r.get('stream_observed')],
        generated_at=dt.datetime.now(dt.timezone.utc).isoformat(),
    )
    if usages:
        keys = sorted({k for u in usages for k in usage_paths(u)})
        out['usage_keys'] = dict(
            keys=keys,
            cached=[k for k in keys if 'cache' in k],
            reasoning=[k for k in keys if 'reasoning' in k],
            note='缓存与推理计数字段缺失，可能是上游未产生，也可能是适配层丢弃。')
    return out


def summarize(rows):
    """Per-run aggregates for both the UI and the exported report."""
    groups = group_rows(rows)
    anomalies = []
    for r in rows:
        for field in ('model', 'system_fingerprint'):
            values = metadata_values(r, field)
            if len(values) > 1:
                anomalies.append(dict(case_id=r.get('case_id'), kind='metadata',
                                      message=f'单次响应内 {field} 出现变化：{values}。请核对原始事件，不据此判断模型身份。'))
    for name, group in groups.items():
        good = [r for r in group if r.get('complete')]
        prompt = _prompt_tokens(good)
        hashes = {r.get('request_sha256') for r in good}
        if len(prompt) > 1 and len(hashes) == 1 and None not in hashes:
            anomalies.append({'case_id': name, 'kind': 'usage',
                'message': f'相同请求体的输入计数出现差异：{prompt}。需核对隐藏上下文、统计口径或处理路径；不能据此确认换模。'})
        if name == 'stop' and any('|' in (r.get('text') or '') for r in good):
            anomalies.append({'case_id': name, 'kind': 'parameter', 'message': '停止符仍出现在正文中，调用链未兑现该停止条件。'})
        if name in ('logprobs', 'top_logprobs') and good and not any(r.get('logprobs_present') for r in good):
            anomalies.append({'case_id': name, 'kind': 'parameter', 'message': '请求被接受，但成功响应均没有概率数据。'})
    summary = []
    for name, group in groups.items():
        good = [r for r in group if r.get('complete')]
        checked = [r for r in good if r.get('validation_pass') is not None]
        prefix = sorted({p for r in good for p in
                         [describe_id(i)['prefix'] for i in (r.get('response_ids') or [])] if p})
        timelines = [stream_timeline(r) for r in good if r.get('stream_observed')]
        timelines = [t for t in timelines if t.get('gap_p50') is not None]
        summary.append(dict(
            case_id=name, category=group[0].get('category'), count=len(group),
            complete=len(good), checked=len(checked),
            passed=sum(bool(r['validation_pass']) for r in checked),
            unique_texts=len({r.get('output_sha256', '') for r in good}),
            normalized_unique_texts=len({(r.get('text') or '').strip() for r in good}),
            median_s=median([r['total_s'] for r in good if type(r.get('total_s')) in (float, int)]),
            ttft_s=median([r['ttft_s'] for r in good if type(r.get('ttft_s')) in (float, int)]),
            prompt_tokens=_prompt_tokens(good), id_prefixes=prefix,
            stream_gap_p50=median([t['gap_p50'] for t in timelines]),
            stream_jitter=median([t['gap_stdev'] for t in timelines if t.get('gap_stdev') is not None])))
    good = [r for r in rows if r.get('complete')]
    return dict(
        count=len(rows), complete=len(good), failed=len(rows) - len(good),
        median_s=median([r['total_s'] for r in good if type(r.get('total_s')) in (float, int)]),
        ttft_s=median([r['ttft_s'] for r in good if type(r.get('ttft_s')) in (float, int)]),
        cases=summary, anomalies=anomalies,
        tokens=tokenizer_signals(rows), logprobs=logprobs_signals(rows), agreement=agreement(rows))
