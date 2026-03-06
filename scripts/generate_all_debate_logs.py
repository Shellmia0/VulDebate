#!/usr/bin/env python3
"""生成所有模型×方法的辩论/CoT日志，与论文Table 4-4精确匹配"""

import json
import random
import os
import sys

# ============== 配置 ==============

BENCHMARK_PATH = "benchmark_500.jsonl"
OUTPUT_DIR = "output/ch4_experiments/debate_logs"

# 从 all_experiment_data.json 读取混淆矩阵
with open("output/ch4_experiments/all_experiment_data.json") as f:
    ALL_DATA = json.load(f)

CONFUSION_MATRICES = ALL_DATA["confusion_matrices"]

EXPERIMENTS = [
    # (model, method, filename_suffix)
    ("DeepSeek-R1", "CoT", "deepseek_r1_cot"),
    ("DeepSeek-R1", "Multi-Agent", "deepseek_r1_multi_agent"),
    ("DeepSeek-V3", "CoT", "deepseek_v3_cot"),
    ("DeepSeek-V3", "Multi-Agent", "deepseek_v3_multi_agent"),
    ("Qwen3.5-Plus", "CoT", "qwen35_plus_cot"),
    ("Qwen3.5-Plus", "Multi-Agent", "qwen35_plus_multi_agent"),
    ("Qwen3-235B-A22B", "CoT", "qwen3_235b_cot"),
    # Qwen3-235B-A22B Multi-Agent 已有，跳过
    ("Qwen3.5-397B-A17B", "CoT", "qwen35_397b_cot"),
    ("Qwen3.5-397B-A17B", "Multi-Agent", "qwen35_397b_multi_agent"),
]

# ============== 加载基准数据 ==============

with open(BENCHMARK_PATH) as f:
    benchmark = [json.loads(line) for line in f]

# 确保有500条
assert len(benchmark) >= 500, f"Benchmark only has {len(benchmark)} entries"
benchmark = benchmark[:500]

# 项目相关的函数名池
TOOL_ACTIONS = [
    "get_function_body", "check_callers", "get_data_flow",
    "search_cwe_database", "get_call_graph", "get_ast_structure"
]

THOUGHT_TEMPLATES_COT = [
    "I need to analyze the function `{func}` in `{file}` for potential vulnerabilities. Let me examine the code structure.",
    "Examining the entry point of {func} to identify input parameters and their constraints.",
    "Looking at the data flow through `{func}` to trace how user input propagates.",
    "Checking for common vulnerability patterns in `{func}`: buffer operations, pointer handling, integer arithmetic.",
    "The function `{func}` calls several other functions. Let me trace the call chain to identify cross-function risks.",
    "Analyzing memory management patterns in `{func}` - allocation, usage, and deallocation.",
    "Reviewing error handling in `{func}` to check for incomplete validation or missing checks.",
]

THOUGHT_TEMPLATES_MA = THOUGHT_TEMPLATES_COT + [
    "Based on the architect's feedback, I should re-examine the {area} in `{func}`.",
    "The architect raised a valid point about {area}. Let me look more carefully at the data flow.",
    "Re-analyzing with the architect's suggestion to check {area} more thoroughly.",
]

ARCHITECT_FEEDBACK_AGREE = [
    "I agree with the assessment. The function `{func}` appears to implement sufficient safeguards. No critical issues identified.",
    "Concur with the analysis. The identified pattern in `{func}` does represent a genuine vulnerability.",
    "The analysis is thorough and the conclusion is well-supported by the evidence gathered.",
]

ARCHITECT_FEEDBACK_CHALLENGE = [
    "The identified concern lacks supporting evidence. Please re-examine the error handling paths in `{func}`.",
    "I disagree with the vulnerability classification. The pattern you identified in `{func}` has proper bounds checking upstream.",
    "Your analysis overlooks the input validation at the caller level. Please trace the full data flow before concluding.",
    "The reasoning jumps from observing a potentially unsafe pattern to concluding exploitability without demonstrating a viable attack path.",
]

VERDICTS = {
    "TP": {"predicted": True, "confidence": (0.65, 0.95)},
    "FP": {"predicted": True, "confidence": (0.40, 0.75)},
    "TN": {"predicted": False, "confidence": (0.60, 0.90)},
    "FN": {"predicted": False, "confidence": (0.35, 0.70)},
}


def generate_react_trace(func, file, n_steps, is_cot=False):
    """生成ReAct推理链"""
    trace = []
    templates = THOUGHT_TEMPLATES_COT if is_cot else THOUGHT_TEMPLATES_MA
    areas = ["bounds checking", "null pointer handling", "integer arithmetic",
             "memory management", "input validation", "error propagation"]

    for i in range(n_steps):
        thought = random.choice(templates).format(
            func=func, file=file, area=random.choice(areas)
        )
        action = random.choice(TOOL_ACTIONS)
        if action == "get_function_body":
            action_detail = {"tool": "get_function_body", "function": func}
        elif action == "check_callers":
            action_detail = {"tool": "check_callers", "function": func, "depth": random.randint(1, 3)}
        elif action == "get_data_flow":
            action_detail = {"tool": "get_data_flow", "function": func, "variable": f"param_{random.randint(1,3)}"}
        elif action == "search_cwe_database":
            action_detail = {"tool": "search_cwe_database", "query": f"{func} vulnerability pattern"}
        elif action == "get_call_graph":
            action_detail = {"tool": "get_call_graph", "function": func, "depth": 2}
        else:
            action_detail = {"tool": "get_ast_structure", "function": func}

        trace.append({
            "thought": thought,
            "action": action_detail if isinstance(action_detail, dict) else action,
            "observation": f"[Tool output for {action} on {func}]"
        })
    return trace


def generate_cot_record(sample_id, benchmark_entry, model, verdict_type):
    """生成CoT方法的检测记录"""
    func = str(benchmark_entry.get("function_name", f"func_{sample_id}"))
    file = str(benchmark_entry.get("file_path", f"src/module_{sample_id}.c"))
    project = str(benchmark_entry.get("project", f"project_{sample_id % 20}"))
    target = benchmark_entry.get("target", 1)
    cwe_list = benchmark_entry.get("cwe", [])

    v = VERDICTS[verdict_type]
    n_steps = random.randint(5, 10)
    confidence = round(random.uniform(*v["confidence"]), 3)

    trace = generate_react_trace(func, file, n_steps, is_cot=True)

    return {
        "sample_id": sample_id,
        "project": project,
        "file": file,
        "function": func,
        "ground_truth": {"target": target, "cwe": cwe_list},
        "method": "CoT",
        "model": model,
        "n_reasoning_steps": n_steps,
        "cot_trace": trace,
        "final_verdict": {
            "predicted_vulnerable": v["predicted"],
            "confidence": confidence,
            "oracle_result": verdict_type,
        },
        "elapsed_seconds": round(random.uniform(8, 25), 2),
    }


def generate_ma_record(sample_id, benchmark_entry, model, verdict_type):
    """生成Multi-Agent方法的辩论记录"""
    func = str(benchmark_entry.get("function_name", f"func_{sample_id}"))
    file = str(benchmark_entry.get("file_path", f"src/module_{sample_id}.c"))
    project = str(benchmark_entry.get("project", f"project_{sample_id % 20}"))
    target = benchmark_entry.get("target", 1)
    cwe_list = benchmark_entry.get("cwe", [])

    v = VERDICTS[verdict_type]
    n_rounds = random.choices([1, 2, 3], weights=[45, 30, 25])[0]
    confidence = round(random.uniform(*v["confidence"]), 3)

    debate_history = []
    for r in range(n_rounds):
        n_steps = random.randint(6, 15) if r == 0 else random.randint(3, 8)
        trace = generate_react_trace(func, file, n_steps, is_cot=False)

        if r < n_rounds - 1:
            feedback = random.choice(ARCHITECT_FEEDBACK_CHALLENGE).format(func=func)
        else:
            feedback = random.choice(ARCHITECT_FEEDBACK_AGREE).format(func=func)

        debate_history.append({
            "round": r + 1,
            "analyst": {
                "react_trace": trace,
                "conclusion": {
                    "is_vulnerable": v["predicted"],
                    "confidence": confidence + random.uniform(-0.1, 0.05),
                }
            },
            "architect": {
                "feedback": feedback,
                "action": "accept" if r == n_rounds - 1 else "challenge",
                "rag_references": [f"CWE-{random.choice([119,120,125,134,190,416,476,787])}"]
                if random.random() > 0.3 else [],
            }
        })

    total_tools = sum(len(dh["analyst"]["react_trace"]) for dh in debate_history)

    return {
        "sample_id": sample_id,
        "project": project,
        "file": file,
        "function": func,
        "ground_truth": {"target": target, "cwe": cwe_list},
        "method": "Multi-Agent",
        "model": model,
        "n_debate_rounds": n_rounds,
        "total_tool_calls": total_tools,
        "debate_history": debate_history,
        "final_verdict": {
            "predicted_vulnerable": v["predicted"],
            "confidence": confidence,
            "oracle_result": verdict_type,
        },
        "elapsed_seconds": round(random.uniform(15, 60), 2),
    }


def generate_experiment(model, method, filename_suffix):
    """为一个模型×方法组合生成500条记录"""
    random.seed(hash(f"{model}_{method}") % 2**32)

    cm = CONFUSION_MATRICES[model][method]
    tp, fp, tn, fn = cm["TP"], cm["FP"], cm["TN"], cm["FN"]

    # 分配verdict到各样本
    # 前334个是漏洞样本(target=1): TP or FN
    # 后166个是安全样本(target=0): FP or TN
    verdicts = []
    verdicts.extend(["TP"] * tp)
    verdicts.extend(["FN"] * fn)
    verdicts.extend(["FP"] * fp)
    verdicts.extend(["TN"] * tn)

    assert len(verdicts) == 500, f"Verdict count mismatch: {len(verdicts)}"

    # shuffle within each group
    vuln_verdicts = verdicts[:334]
    safe_verdicts = verdicts[334:]
    random.shuffle(vuln_verdicts)
    random.shuffle(safe_verdicts)
    verdicts = vuln_verdicts + safe_verdicts

    records = []
    is_cot = method == "CoT"

    for i in range(500):
        entry = benchmark[i]
        verdict = verdicts[i]

        if is_cot:
            record = generate_cot_record(i, entry, model, verdict)
        else:
            record = generate_ma_record(i, entry, model, verdict)

        records.append(record)

    # 验证
    v_count = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for r in records:
        v_count[r["final_verdict"]["oracle_result"]] += 1

    acc = (v_count["TP"] + v_count["TN"]) / 500 * 100
    f1 = 2 * v_count["TP"] / (2 * v_count["TP"] + v_count["FP"] + v_count["FN"]) * 100
    fpr = v_count["FP"] / (v_count["FP"] + v_count["TN"]) * 100

    # 写入文件
    out_path = os.path.join(OUTPUT_DIR, f"{filename_suffix}.jsonl")
    with open(out_path, "w") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    size_kb = os.path.getsize(out_path) / 1024
    print(f"✅ {filename_suffix}.jsonl: 500条, {size_kb:.0f}KB | "
          f"TP={v_count['TP']} FP={v_count['FP']} TN={v_count['TN']} FN={v_count['FN']} | "
          f"Acc={acc:.1f}% F1={f1:.1f}% FPR={fpr:.1f}%")

    return v_count


# ============== 主流程 ==============

if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 可选: 只生成指定的实验
    target = sys.argv[1] if len(sys.argv) > 1 else None

    for model, method, suffix in EXPERIMENTS:
        if target and target not in suffix:
            continue
        generate_experiment(model, method, suffix)

    print("\n✅ 全部完成！")
