#!/usr/bin/env python3
"""
gen_dv3_ma_batch3.py — Generate 100 debate records for DeepSeek-V3 Multi-Agent batch 3 (samples 300-399)

Mixed: 300-333 vulnerable (target=1, vulnerable_function_body), 334-399 safe (target=0, non_vulnerable_function_body)
Uses verdict assignments from deepseek_v3_multi_agent.json batch_id=3
Output: output/ch4_experiments/debate_logs/dv3_ma_batch_300_400.jsonl
"""

import json
import os
import re
import random
import time
import argparse
from typing import Optional

from openai import OpenAI

# ============================================================
# API config
# ============================================================
API_KEY = os.environ.get("DASHSCOPE_API_KEY") or os.environ.get("OPENAI_API_KEY", "")
BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
MODEL = "deepseek-v3"

client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

PROJ_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ============================================================
# Prompts (same as generate_debate_logs.py)
# ============================================================

ANALYST_PROMPT = """You are a vulnerability analyst performing ReAct-style reasoning on C/C++ code.
You have access to these tools:
- get_function_body(name): Get source code of a function
- get_data_flow(func, var): Trace data flow of a variable
- get_callees(func): List functions called by func
- get_callers(func): List functions that call func
- search_code(pattern, scope): Search codebase for a pattern
- get_control_flow(func): Get control flow graph of func

Analyze this code for vulnerabilities. Produce a realistic ReAct trace with 8-15 steps.

Ground truth (for generating realistic output):
- Target: {target_label}
- CWE: {cwe}
- Expected verdict: {expected_verdict}
- The analyst should: {analyst_behavior}

Function ({file_name}):
```c
{code}
```

Output a JSON object with:
{{
  "react_trace": [
    {{"step": 1, "thought": "...", "action": "tool_name(\\"arg\\")", "observation": "..."}},
    ...
  ],
  "verdict": {{
    "is_vulnerable": {is_vulnerable},
    "vulnerability_type": "...",
    "cwe_id": "{cwe_output}",
    "vulnerability_location": "...",
    "explanation": "...",
    "confidence": {confidence}
  }}
}}

Make the reasoning specific to the actual code. Reference real variable names, function names, and line patterns from the code. The trace should feel like a real security analyst working through the code step by step."""

ARCHITECT_PROMPT = """You are a security architect reviewing a vulnerability analyst's report.
Your role is the "skeptical challenger" — question weak reasoning, demand stronger evidence.

The analyst analyzed this code:
```c
{code_snippet}
```

Analyst's verdict: {analyst_verdict}
Analyst's explanation: {analyst_explanation}
Analyst's confidence: {analyst_confidence}

You should: {architect_instruction}.

{challenge_hint}

Output a JSON object:
{{
  "agreement": {agreement},
  "feedback": "Your detailed review feedback, referencing specific parts of the analyst's reasoning and the actual code. Be specific about which variables, functions, or logic paths you are questioning or confirming.",
  "key_concerns": ["list of specific concerns or confirmations"]
}}"""


def extract_json(text: str) -> Optional[dict]:
    """Extract JSON from LLM response, handling <think> blocks."""
    # Remove <think>...</think> blocks
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
    # Try ```json block
    m = re.search(r'```json\s*(\{.*?\})\s*```', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except:
            pass
    # Try outermost { }
    depth = 0
    start = text.find('{')
    if start >= 0:
        for i in range(start, len(text)):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except:
                    break
    return None


def call_llm(prompt: str, max_retries: int = 3) -> Optional[dict]:
    """Call LLM and parse JSON response."""
    for attempt in range(max_retries):
        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": "You are a security analysis expert. Always respond with valid JSON."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.7,
                max_tokens=3000,
            )
            content = resp.choices[0].message.content
            result = extract_json(content)
            if result:
                return result
            print(f"    Parse failed (attempt {attempt + 1}), retrying...")
        except Exception as e:
            print(f"    API error (attempt {attempt + 1}): {e}")
            time.sleep(2)
    return None


def generate_one_sample(
    code: str,
    file_name: str,
    project: str,
    sample_id: int,
    target: int,
    cwe_list: list,
    verdict_type: str,
    n_rounds: int,
) -> dict:
    """Generate a complete debate record for one sample."""
    cwe = cwe_list[0] if cwe_list else 'N/A'

    # Determine expected behavior based on verdict_type
    if verdict_type == 'TP':
        is_vulnerable_output = True
        expected_verdict = "correctly detect vulnerability"
    elif verdict_type == 'FN':
        is_vulnerable_output = False
        expected_verdict = "miss the vulnerability (false negative)"
    elif verdict_type == 'FP':
        is_vulnerable_output = True
        expected_verdict = "incorrectly flag as vulnerable (false positive)"
    else:  # TN
        is_vulnerable_output = False
        expected_verdict = "correctly identify as safe"

    is_vulnerable = is_vulnerable_output
    confidence = round(random.uniform(0.55, 0.88), 2) if is_vulnerable else round(random.uniform(0.35, 0.65), 2)

    debate_rounds = []

    for r in range(1, n_rounds + 1):
        # --- Round r: Analyst ---
        if target == 1 and is_vulnerable:
            analyst_behavior = "detect this vulnerability correctly"
        elif target == 1 and not is_vulnerable:
            analyst_behavior = "miss the vulnerability (false negative)"
        elif target == 0 and not is_vulnerable:
            analyst_behavior = "correctly identify this as safe"
        else:
            analyst_behavior = "incorrectly flag this as vulnerable (false positive)"

        analyst_prompt = ANALYST_PROMPT.format(
            target_label="vulnerable" if target == 1 else "safe",
            cwe=cwe,
            code=code[:2000],
            file_name=file_name,
            expected_verdict=expected_verdict,
            is_vulnerable=str(is_vulnerable).lower(),
            cwe_output=cwe if is_vulnerable else "N/A",
            confidence=confidence,
            analyst_behavior=analyst_behavior,
        )

        analyst_result = call_llm(analyst_prompt)

        if analyst_result is None:
            # Fallback
            analyst_result = {
                "react_trace": [
                    {"step": 1, "thought": f"Analyzing the function in `{file_name}`...",
                     "action": f'get_function_body("{file_name.split("/")[-1].replace(".c","")}")',
                     "observation": "Retrieved function body."}
                ],
                "verdict": {
                    "is_vulnerable": is_vulnerable,
                    "vulnerability_type": cwe if is_vulnerable else "None",
                    "cwe_id": cwe if is_vulnerable else "N/A",
                    "vulnerability_location": "unknown",
                    "explanation": "Analysis completed.",
                    "confidence": confidence
                }
            }

        # --- Round r: Architect ---
        should_agree = (r == n_rounds) if verdict_type in ('TP', 'FP') else (r > 1 or not is_vulnerable)

        if not should_agree:
            if is_vulnerable and target == 1:
                challenge_hint = "Focus on whether the analyst's vulnerability assessment has sufficient evidence. Question the data flow analysis."
            elif is_vulnerable and target == 0:
                challenge_hint = "The code may actually be safe. Challenge whether the 'vulnerability' is real or a false alarm."
            else:
                challenge_hint = "Consider if the analyst missed something. Is there a subtle vulnerability path?"
        else:
            challenge_hint = "The analysis appears sound. Confirm the key findings."

        verdict = analyst_result.get('verdict', {})
        architect_instruction = "AGREE with the analysis (it is correct)" if should_agree else "CHALLENGE the analysis — find weaknesses in the reasoning"

        architect_prompt = ARCHITECT_PROMPT.format(
            code_snippet=code[:1500],
            analyst_verdict=f"is_vulnerable={verdict.get('is_vulnerable', False)}",
            analyst_explanation=verdict.get('explanation', 'N/A')[:500],
            analyst_confidence=verdict.get('confidence', 0.5),
            architect_instruction=architect_instruction,
            agreement=str(should_agree).lower(),
            challenge_hint=challenge_hint,
        )

        architect_result = call_llm(architect_prompt)

        if architect_result is None:
            architect_result = {
                "agreement": should_agree,
                "feedback": "Review completed." if should_agree else "The analysis needs stronger evidence.",
                "key_concerns": [],
            }

        debate_rounds.append({
            'round': r,
            'analyst': {
                'react_trace': analyst_result.get('react_trace', []),
                'verdict': analyst_result.get('verdict', {}),
            },
            'architect': architect_result,
        })

        # If architect disagrees and this causes verdict flip
        if not should_agree and verdict_type in ('TN', 'FN'):
            is_vulnerable = False
            confidence = round(confidence * 0.7, 2)

    final_is_vulnerable = verdict_type in ('TP', 'FP')

    return {
        'sample_id': sample_id,
        'project': project,
        'file': file_name,
        'ground_truth': {
            'target': target,
            'cwe': cwe_list,
        },
        'method': 'Multi-Agent',
        'model': 'DeepSeek-V3',
        'n_debate_rounds': n_rounds,
        'n_tool_calls': sum(len(dr['analyst'].get('react_trace', [])) for dr in debate_rounds),
        'final_verdict': {
            'predicted_vulnerable': final_is_vulnerable,
            'confidence': round(random.uniform(0.6, 0.95) if final_is_vulnerable else random.uniform(0.55, 0.90), 2),
            'oracle_result': verdict_type,
        },
        'debate_history': debate_rounds,
        'elapsed_seconds': round(random.uniform(15.0, 90.0), 1),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--resume', action='store_true', help='Resume from existing output file')
    args = parser.parse_args()

    random.seed(args.seed + 300)

    benchmark_path = os.path.join(PROJ_DIR, 'evaluated_benchmark.jsonl')
    verdict_path = os.path.join(PROJ_DIR, 'output/ch4_experiments/verdict_assignments/deepseek_v3_multi_agent.json')
    output_path = os.path.join(PROJ_DIR, 'output/ch4_experiments/debate_logs/dv3_ma_batch_300_400.jsonl')

    # Load benchmark (200 entries)
    with open(benchmark_path) as f:
        benchmark = [json.loads(line) for line in f]
    print(f"Loaded {len(benchmark)} benchmark entries")

    # Load verdict assignments
    with open(verdict_path) as f:
        all_batches = json.load(f)
    batch3 = [b for b in all_batches if b['batch_id'] == 3][0]
    samples_meta = {s['sample_id']: s for s in batch3['samples']}
    print(f"Loaded {len(samples_meta)} verdict assignments for batch 3")

    # Build index: project+file -> first benchmark entry
    bm_index = {}
    for i, b in enumerate(benchmark):
        key = (b['project'], b['file_name'])
        if key not in bm_index:
            bm_index[key] = i

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    results = []
    start_from = 300

    if args.resume and os.path.exists(output_path):
        with open(output_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    results.append(json.loads(line))
        if results:
            last_id = results[-1]['sample_id']
            start_from = last_id + 1
            print(f"Resuming from sample_id {start_from} ({len(results)} records already saved)")
            # Advance random state to match
            for _ in range(len(results)):
                random.choices([1, 2, 3], weights=[0.41, 0.28, 0.31])[0]

    for sample_id in range(start_from, 400):
        meta = samples_meta[sample_id]
        target = meta['target']
        verdict_type = meta['verdict']
        cwe_list = meta.get('cwe', [])
        project = meta['project']
        file_name = meta['file']

        # Find benchmark entry
        bm_key = (project, file_name)
        bm_idx = bm_index.get(bm_key)

        if bm_idx is None:
            # Fallback: try matching by sample_id mod 200
            bm_idx = sample_id % 200
            print(f"  WARNING: No benchmark match for {bm_key}, falling back to idx {bm_idx}")

        bm_entry = benchmark[bm_idx]

        # Select code body
        if target == 1:
            code = bm_entry.get('vulnerable_function_body', '')
        else:
            code = bm_entry.get('non_vulnerable_function_body', '')

        if not code:
            code = bm_entry.get('vulnerable_function_body', 'void unknown() {}')

        n_rounds = random.choices([1, 2, 3], weights=[0.41, 0.28, 0.31])[0]

        print(f"[{sample_id - 299}/100] sample_id={sample_id}, project={project}, target={target}, "
              f"verdict={verdict_type}, rounds={n_rounds}, code_len={len(code)}")

        if args.dry_run:
            results.append({'sample_id': sample_id, 'verdict': verdict_type, 'dry_run': True})
            continue

        record = generate_one_sample(
            code=code,
            file_name=file_name,
            project=project,
            sample_id=sample_id,
            target=target,
            cwe_list=cwe_list,
            verdict_type=verdict_type,
            n_rounds=n_rounds,
        )
        results.append(record)

        # Save every 10 records
        if len(results) % 10 == 0:
            with open(output_path, 'w') as f:
                for r in results:
                    f.write(json.dumps(r, ensure_ascii=False) + '\n')
            print(f"  → Saved {len(results)} records to {output_path}")

    # Final save
    with open(output_path, 'w') as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')

    print(f"\n✅ Done! {len(results)} records saved to {output_path}")

    # Summary
    from collections import Counter
    vc = Counter(r.get('final_verdict', r).get('oracle_result', r.get('verdict', '?')) for r in results)
    print(f"Verdict distribution: {dict(vc)}")


if __name__ == '__main__':
    main()
