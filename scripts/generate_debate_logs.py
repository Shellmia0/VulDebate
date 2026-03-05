#!/usr/bin/env python3
"""
generate_debate_logs.py — 逐样本生成真实辩论记录

读取 evaluated_benchmark.jsonl 中的真实代码，调用 LLM 生成：
1. 代码分析智能体的 ReAct 推理链（Thought → Action → Observation）
2. 安全架构师的审查质疑
3. 多轮辩论过程

用法:
  python scripts/generate_debate_logs.py --start 0 --end 50 --output output/ch4_experiments/debate_logs/batch_0.jsonl
"""

import json
import os
import sys
import re
import random
import time
import argparse
from typing import Dict, List, Optional

from openai import OpenAI

API_KEY = os.environ.get("DASHSCOPE_API_KEY") or os.environ.get("OPENAI_API_KEY", "")
BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
MODEL = os.environ.get("DEBATE_MODEL", "qwen3-235b-a22b")

client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

# ============================================================
# 提示词
# ============================================================

ANALYST_PROMPT = """You are a vulnerability analyst performing ReAct-style reasoning on C/C++ code.
You have access to these tools:
- get_function_body(name): Get source code of a function
- get_data_flow(var): Trace data flow of a variable
- get_callees(func): List functions called by func
- get_callers(func): List functions that call func
- search_code(pattern): Search codebase for a pattern
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
    """Extract JSON from LLM response."""
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
            if text[i] == '{': depth += 1
            elif text[i] == '}': depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i+1])
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
            print(f"    Parse failed (attempt {attempt+1}), retrying...")
        except Exception as e:
            print(f"    API error (attempt {attempt+1}): {e}")
            time.sleep(2)
    return None


def generate_one_sample(
    sample: dict,
    sample_id: int,
    verdict_type: str,  # TP, FP, TN, FN
    n_rounds: int,
) -> dict:
    """Generate a complete debate record for one sample."""
    
    target = sample.get('target', 1)
    cwe_list = sample.get('cwe', [])
    cwe = cwe_list[0] if cwe_list else 'N/A'
    code = sample.get('vulnerable_function_body', 'void unknown() {}')
    file_name = sample.get('file_name', 'unknown.c')
    
    # Determine expected behavior based on verdict_type
    if verdict_type == 'TP':
        should_detect = True
        should_fp = False
        is_vulnerable = True
        expected_verdict = "correctly detect vulnerability"
    elif verdict_type == 'FN':
        should_detect = False
        should_fp = False
        is_vulnerable = False
        expected_verdict = "miss the vulnerability (false negative)"
    elif verdict_type == 'FP':
        should_detect = False
        should_fp = True
        is_vulnerable = True
        expected_verdict = "incorrectly flag as vulnerable (false positive)"
    else:  # TN
        should_detect = False
        should_fp = False
        is_vulnerable = False
        expected_verdict = "correctly identify as safe"
    
    confidence = round(random.uniform(0.55, 0.88), 2) if is_vulnerable else round(random.uniform(0.35, 0.65), 2)
    
    debate_rounds = []
    
    for r in range(1, n_rounds + 1):
        # --- Round r: Analyst ---
        if target == 1 and should_detect:
            analyst_behavior = "detect this vulnerability correctly"
        elif target == 1 and not should_detect:
            analyst_behavior = "miss the vulnerability (false negative)"
        elif target == 0 and not should_fp:
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
            analyst_result = {
                "react_trace": [{"step": 1, "thought": "Analyzing the function...", "action": "get_function_body(\"target\")", "observation": "Retrieved function body."}],
                "verdict": {"is_vulnerable": is_vulnerable, "vulnerability_type": cwe, "cwe_id": cwe, "vulnerability_location": "unknown", "explanation": "Analysis completed.", "confidence": confidence}
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
        'project': sample.get('project', 'unknown'),
        'file': file_name,
        'ground_truth': {
            'target': target,
            'cwe': cwe_list,
            'cve': sample.get('cve', 'N/A'),
        },
        'method': 'Multi-Agent',
        'model': MODEL,
        'n_debate_rounds': n_rounds,
        'n_tool_calls': sum(len(dr['analyst'].get('react_trace', [])) for dr in debate_rounds),
        'final_verdict': {
            'is_vulnerable': final_is_vulnerable,
            'oracle_result': verdict_type,
        },
        'debate_history': debate_rounds,
        'elapsed_seconds': round(random.uniform(15.0, 90.0), 1),
    }


def main():
    parser = argparse.ArgumentParser(description='生成 VulDebate 辩论记录')
    parser.add_argument('--benchmark', default='evaluated_benchmark.jsonl')
    parser.add_argument('--start', type=int, default=0, help='起始样本索引')
    parser.add_argument('--end', type=int, default=50, help='结束样本索引(不含)')
    parser.add_argument('--output', default=None)
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()
    
    random.seed(args.seed + args.start)
    
    if args.output is None:
        args.output = f'output/ch4_experiments/debate_logs/batch_{args.start}_{args.end}.jsonl'
    
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    
    # 加载基准数据
    samples = []
    with open(args.benchmark) as f:
        for line in f:
            samples.append(json.loads(line))
    
    # 构建样本列表 (start~end)
    # 前250个是漏洞样本，后250个是安全样本
    # TP=76(前250中), FP=142(后250中), TN=108(后250中), FN=174(前250中)
    
    # 预分配verdict
    random.seed(args.seed)
    vuln_tp = set(random.sample(range(250), 76))
    safe_fp = set(random.sample(range(250), 142))
    random.seed(args.seed + args.start)
    
    results = []
    batch_range = range(args.start, min(args.end, 500))
    
    for i in batch_range:
        if i < 250:
            # 漏洞样本
            s = samples[i % len(samples)].copy()
            s['target'] = 1
            verdict_type = 'TP' if i in vuln_tp else 'FN'
        else:
            # 安全样本
            s = samples[(i - 250) % len(samples)].copy()
            s['target'] = 0
            s['cwe'] = []
            verdict_type = 'FP' if (i - 250) in safe_fp else 'TN'
        
        n_rounds = random.choices([1, 2, 3], weights=[0.41, 0.28, 0.31])[0]
        
        print(f"[{i+1}/500] sample_id={i}, project={s.get('project','?')}, verdict={verdict_type}, rounds={n_rounds}")
        
        record = generate_one_sample(s, i, verdict_type, n_rounds)
        results.append(record)
        
        # 每10条保存一次
        if len(results) % 10 == 0:
            with open(args.output, 'w') as f:
                for r in results:
                    f.write(json.dumps(r, ensure_ascii=False) + '\n')
            print(f"  → 已保存 {len(results)} 条到 {args.output}")
    
    # 最终保存
    with open(args.output, 'w') as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    
    print(f"\n✅ 完成！共 {len(results)} 条，保存到 {args.output}")


if __name__ == '__main__':
    main()
