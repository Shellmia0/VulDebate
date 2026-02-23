import json
import os
import argparse
from vulnerability_analyst import VulnerabilityAnalyst
from security_architect import SecurityArchitect
from evaluation_oracle import EvaluationOracle
# Backward-compatible aliases
ReActAgent = VulnerabilityAnalyst
ReflexionAgent = SecurityArchitect
EvaluationAgent = EvaluationOracle
import tools
from datetime import datetime
import difflib
from langchain_core.tools import tool
from multiprocessing import Pool, Manager
import multiprocessing as mp

# Initialize agents for this process (will be re-initialized with correct model in main)
react_agent = None
reflexion_agent = None
evaluation_agent = None

def _extract_json_from_raw(raw):
    """Extract any JSON object from raw string. Returns parsed dict or None."""
    import re
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    # Try ```json block
    m = re.search(r'```json\s*(\{.*?\})\s*```', raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except:
            pass
    # Try outermost { }
    start_idx = raw.find('{')
    if start_idx >= 0:
        depth = 0
        for i in range(start_idx, len(raw)):
            if raw[i] == '{': depth += 1
            elif raw[i] == '}': depth -= 1
            if depth == 0:
                try:
                    return json.loads(raw[start_idx:i+1])
                except:
                    pass
                break
    return None


def _repair_json_with_llm(raw_output, model_name=None):
    """Last resort: ask LLM to extract JSON from malformed output."""
    from openai import OpenAI
    client = OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY"),
        base_url=os.environ.get("OPENAI_BASE_URL"),
    )
    repair_prompt = f"""The following is a vulnerability analysis output that contains a JSON verdict, but it may be malformed or incomplete. Extract ONLY the JSON object with these exact fields:
- is_vulnerable (boolean)
- vulnerability_type (string)  
- cwe_id (string)
- explanation (string, brief)

If the analysis concluded the code is vulnerable, set is_vulnerable=true. If safe, set is_vulnerable=false.
If you cannot determine the verdict, default to is_vulnerable=true (conservative).

Raw output:
{str(raw_output)[:3000]}

Reply with ONLY the JSON object, nothing else."""
    
    resp = client.chat.completions.create(
        model=model_name or os.environ.get("REPAIR_MODEL", "qwen3-235b-a22b"),
        messages=[{"role": "user", "content": repair_prompt}],
        temperature=0,
        max_tokens=256,
    )
    text = resp.choices[0].message.content
    parsed = _extract_json_from_output(text)
    if parsed is None:
        parsed = _extract_json_from_raw(text)
    return parsed


def _parse_react_output_with_retry(react_agent, function_input, debate_history=None, max_retries=3):
    """Call VulnerabilityAnalyst and parse output with retries + LLM repair fallback."""
    last_raw = None
    for attempt in range(max_retries):
        if debate_history is not None:
            react_output = safe_api_call(react_agent.predict, function_input, debate_history)
        else:
            react_output = safe_api_call(react_agent.predict, function_input)
        parsed = _extract_json_from_output(react_output['output'])
        if parsed is not None:
            react_output['output'] = parsed
            return react_output
        last_raw = react_output['output']
        print(f"  [VulnAnalyst retry {attempt+1}/{max_retries}] JSON parse failed, retrying...")
    
    # Last resort: LLM repair
    print(f"  [VulnAnalyst] All retries failed, attempting LLM repair...")
    try:
        repaired = _repair_json_with_llm(last_raw)
        if repaired and 'is_vulnerable' in repaired:
            print(f"  [VulnAnalyst] LLM repair succeeded: is_vulnerable={repaired['is_vulnerable']}")
            react_output['output'] = repaired
            return react_output
    except Exception as e:
        print(f"  [VulnAnalyst] LLM repair failed: {e}")
    
    raise ValueError(f"VulnerabilityAnalyst output parse failed after {max_retries} attempts + LLM repair")


def _repair_reflexion_with_llm(raw_output, model_name=None):
    """Last resort: ask LLM to extract SecurityArchitect JSON from malformed output."""
    from openai import OpenAI
    client = OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY"),
        base_url=os.environ.get("OPENAI_BASE_URL"),
    )
    repair_prompt = f"""The following is a security review output. Extract ONLY the JSON object with these exact fields:
- agreement (boolean): does the reviewer agree with the analysis?
- feedback (string): the reviewer's feedback

Raw output:
{str(raw_output)[:3000]}

Reply with ONLY the JSON object, nothing else."""
    
    resp = client.chat.completions.create(
        model=model_name or os.environ.get("REPAIR_MODEL", "qwen3-235b-a22b"),
        messages=[{"role": "user", "content": repair_prompt}],
        temperature=0,
        max_tokens=256,
    )
    text = resp.choices[0].message.content
    return _extract_json_from_raw(text)


def _parse_reflexion_output_with_retry(reflexion_agent, function_code, react_output, max_retries=3):
    """Call SecurityArchitect and parse output with retries + LLM repair fallback."""
    last_raw = None
    for attempt in range(max_retries):
        reflexion_output = reflexion_agent.reflect_on_analysis(function_code, react_output)
        parsed = _extract_json_from_raw(str(reflexion_output['output']))
        if parsed is not None and 'agreement' in parsed:
            reflexion_output['output'] = parsed
            return reflexion_output
        last_raw = reflexion_output['output']
        print(f"  [SecArchitect retry {attempt+1}/{max_retries}] JSON parse failed, retrying...")
    
    # Last resort: LLM repair
    print(f"  [SecArchitect] All retries failed, attempting LLM repair...")
    try:
        repaired = _repair_reflexion_with_llm(last_raw)
        if repaired and 'agreement' in repaired:
            print(f"  [SecArchitect] LLM repair succeeded: agreement={repaired['agreement']}")
            reflexion_output['output'] = repaired
            return reflexion_output
    except Exception as e:
        print(f"  [SecArchitect] LLM repair failed: {e}")
    
    raise ValueError(f"SecurityArchitect output parse failed after {max_retries} attempts + LLM repair")


def _extract_json_from_output(raw):
    """Extract JSON object containing 'is_vulnerable' from raw LLM output.
    Returns parsed dict or None if extraction fails."""
    import re
    if isinstance(raw, dict) and 'is_vulnerable' in raw:
        return raw
    if not isinstance(raw, str):
        return None
    # Try ```json block first
    m = re.search(r'```json\s*(\{.*?\})\s*```', raw, re.DOTALL)
    if m:
        try:
            obj = json.loads(m.group(1))
            if 'is_vulnerable' in obj:
                return obj
        except:
            pass
    # Try finding outermost { } containing is_vulnerable
    start_idx = raw.find('{')
    if start_idx >= 0:
        depth = 0
        for i in range(start_idx, len(raw)):
            if raw[i] == '{': depth += 1
            elif raw[i] == '}': depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(raw[start_idx:i+1])
                    if 'is_vulnerable' in obj:
                        return obj
                except:
                    pass
                break
    # Try regex for is_vulnerable pattern
    m = re.search(r'\{[^{}]*"is_vulnerable"[^{}]*\}', raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except:
            pass
    return None


def iterative_debate(react_agent, reflexion_agent, function_name, function_code, max_rounds=5):
    """
    Conduct an iterative debate between ReAct and Reflexion agents until consensus or max rounds
    """
    debate_history = []
    round_num = 1
    
    # Initial ReAct analysis (with retry on parse failure)
    print(f"Round {round_num}: ReAct Agent initial analysis...")
    react_output = _parse_react_output_with_retry(react_agent, function_name)
    try:
        traj_parts = []
        for i, output in enumerate(react_output['intermediate_steps']):
            if i != len(react_output['intermediate_steps'])-1:
                action = output[0]
                obs = output[1]
                log_text = action.log if hasattr(action, 'log') else str(action)
                traj_parts.append(f"Thought: {log_text}\n\nObservation: {obs}\n")
            else:
                if hasattr(output, 'log'):
                    traj_parts.append(f"Thought: {output.log}")
                elif isinstance(output, tuple):
                    action = output[0]
                    log_text = action.log if hasattr(action, 'log') else str(action)
                    traj_parts.append(f"Thought: {log_text}")
                else:
                    traj_parts.append(f"Thought: {str(output)}")
        trajectory = "\n".join(traj_parts)
    except Exception as e:
        trajectory = f"Error extracting trajectory: {e}\nRaw output: {react_output.get('output', '')}"
    react_output['trajectory'] = trajectory
    debate_history.append({
        "round": round_num,
        "agent": "ReAct",
        "input": react_output['input'],
        "output": react_output['output'],
        "trajectory": react_output['trajectory']
    })
    
    # Initial Reflexion review (with retry on parse failure)
    print(f"Round {round_num}: Reflexion Agent reviewing...")
    reflexion_output = _parse_reflexion_output_with_retry(reflexion_agent, function_code, react_output)
    print(f"Reflexion:\n{reflexion_output['output']}")

    debate_history.append({
        "round": round_num,
        "agent": "Reflexion", 
        "input": reflexion_output['input'],
        "output": reflexion_output['output']
    })
    
    # Check for agreement 
    agree = reflexion_output['output']['agreement']
    
    if agree:
        print(f"Agents reached consensus in round {round_num}")
        # final_decision = react_decision
    else:
        print(f"Agents disagree. Starting iterative debate...")
        
        # Continue debate until agreement or max rounds
        for round_num in range(2, max_rounds + 1):
            print(f"\nRound {round_num}: Debate continues...")
            react_output = _parse_react_output_with_retry(react_agent, function_code, debate_history)
            try:
                traj_parts2 = []
                for i, output in enumerate(react_output['intermediate_steps']):
                    if i != len(react_output['intermediate_steps'])-1:
                        action = output[0]
                        obs = output[1]
                        log_text = action.log if hasattr(action, 'log') else str(action)
                        traj_parts2.append(f"Thought: {log_text}\n\nObservation: {obs}\n")
                    else:
                        if hasattr(output, 'log'):
                            traj_parts2.append(f"Thought: {output.log}")
                        elif isinstance(output, tuple):
                            action = output[0]
                            log_text = action.log if hasattr(action, 'log') else str(action)
                            traj_parts2.append(f"Thought: {log_text}")
                        else:
                            traj_parts2.append(f"Thought: {str(output)}")
                trajectory = "\n".join(traj_parts2)
            except Exception as e:
                trajectory = f"Error: {e}\nRaw: {react_output.get('output', '')}"
            react_output['trajectory'] = trajectory
            debate_history.append({
                "round": round_num,
                "agent": "ReAct",
                "input": react_output['input'],
                "output": react_output['output'],
                "trajectory": react_output['trajectory']
            })
            
            reflexion_output = _parse_reflexion_output_with_retry(reflexion_agent, function_code, react_output)
            print(f"Reflexion:\n{reflexion_output['output']}")
    
            debate_history.append({
                "round": round_num,
                "agent": "Reflexion",
                "input": reflexion_output['input'],
                "output": reflexion_output['output']
            })
            
            agree = reflexion_output['output']['agreement']

            if agree:
                print(f"Agents reached consensus in round {round_num}")
                break

        if agree:
            pass
        else:
            print(f"No consensus reached after {max_rounds} rounds. Using final positions...")
    
    # Decision logic: incorporate debate history
    # If Analyst ever judged "not vulnerable" in any round, the debate
    # successfully challenged the initial claim → accept "not vulnerable".
    # This captures the core value of multi-agent debate: the Architect's
    # critique can cause the Analyst to change its mind.
    analyst_verdicts = []
    for entry in debate_history:
        if entry['agent'] == 'ReAct':
            out = entry['output']
            if isinstance(out, dict):
                v = out.get('is_vulnerable', True)
                if isinstance(v, str):
                    v = v.lower() in ('true', '1', 'yes')
                analyst_verdicts.append(v)
    
    # If analyst ever said "not vulnerable" during debate, accept that
    if False in analyst_verdicts:
        final_vulnerable = False
    # Otherwise use last analyst verdict
    elif analyst_verdicts:
        final_vulnerable = analyst_verdicts[-1]
    else:
        final_vulnerable = True  # fallback
    
    return {
        "debate_history": debate_history,
        "consensus_reached": agree,
        "is_vulnerable": final_vulnerable,
    }

def safe_api_call(func, *args, **kwargs):
    return func(*args, **kwargs)

def log_debate_result(function_name, function_body, project, function_type, debate_result, log_file="vulnerability_analysis_log.txt"):
    """
    Log the complete debate result to a text file in real-time
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    detection_result = "Vulnerable "if debate_result['debate_history'][-2]['output']['is_vulnerable'] else "Benign"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*80}\n")
        f.write(f"TIMESTAMP: {timestamp}\n")
        f.write(f"PROJECT: {project}\n")
        f.write(f"FUNCTION: {function_name}\n")
        f.write(f"TYPE: {function_type.upper()}\n")
        f.write(f"FINAL CONSENSUS DECISION: {detection_result}\n")
        # f.write(f"ROUNDS NEEDED: {debate_result['rounds_needed']}\n")
        f.write(f"CONSENSUS REACHED: {debate_result['consensus_reached']}\n")
        f.write(f"{'='*80}\n")
        
        # Add the actual function body
        f.write(f"FUNCTION BODY:\n")
        f.write(f"{'-'*40}\n")
        f.write(f"{function_body}\n")
        f.write(f"{'-'*40}\n")
        
        # Add complete debate history
        f.write(f"COMPLETE DEBATE HISTORY:\n")
        f.write(f"{'-'*40}\n")
        for entry in debate_result["debate_history"]:
            f.write(f"\nRound {entry['round']} - {entry['agent']}:\n")
            if entry.get('output'):
                f.write(f"Assessment: {entry['output']}\n")
            f.write(f"{'--------------------'}\n")
        
        f.write(f"\n")
        f.flush()  # Ensure immediate write to file

def initialize_log_file(log_file="vulnerability_analysis_log.txt"):
    """
    Initialize the log file with a header
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(f"VULNERABILITY ANALYSIS LOG\n")
        f.write(f"Started: {timestamp}\n")
        f.write(f"{'='*80}\n")
        f.write(f"This file tracks all functions analyzed and vulnerability detections\n")
        f.write(f"{'='*80}\n")

def vuln(vuln_func_name, item, react_agent, reflexion_agent, evaluation_agent):
    # Process Vulnerable function
    print(f"\n[VULNERABLE FUNCTION ANALYSIS - Process {os.getpid()}]")
    print(f"Function: {vuln_func_name}")
    print("-" * 50)
    
    @tool("get_callers")
    def get_callers_vuln(function_name: str) -> str:
        """Returns a JSON list of functions that call the given function."""
        return tools.get_callers.invoke({"function_name": function_name, "caller_graph": item["vulnerable_caller_graph"]})
    
    @tool("get_callees") 
    def get_callees_vuln(function_name: str) -> str:
        """Returns a JSON list of functions called by the given function."""
        return tools.get_callees.invoke({"function_name": function_name, "callee_graph": item["vulnerable_callee_graph"]})
    
    @tool("get_function_body")
    def get_function_body_vuln(function_name: str) -> str:
        """Retrieves the body of a function as a string."""
        return tools.get_function_body.invoke({
            "function_name": function_name,
            "function_bodies": item["vulnerable_function_bodies"], 
            "project_url": item.get("project_url"),
            "commit_id": item.get("vulnerability_fixing_commit_id"),
            "file_name": item.get("file_name")
        })
    
    react_agent.set_tools([get_callers_vuln, get_callees_vuln, get_function_body_vuln])
    
    # Conduct iterative debate between agents
    print("Starting iterative debate for vulnerable function...")
    print("-" * 50)

    if item["non_vulnerable_function_body"][0:2] == 'c\n':
        non_vuln_func_code = item["non_vulnerable_function_body"][2:]
    elif item["non_vulnerable_function_body"][0:4] == 'cpp\n':
        non_vuln_func_code = item["non_vulnerable_function_body"][4:]
    else:
        non_vuln_func_code = item["non_vulnerable_function_body"]
    vuln_func_code = item["vulnerable_function_body"]
    debate_result_vuln = iterative_debate(
        react_agent, reflexion_agent, 
        vuln_func_name, vuln_func_code, max_rounds=3
    )
    
    # EVALUATION STEP - Evaluate the analysis
    print(f"\n[EVALUATION STEP FOR {vuln_func_name}]")
    print("-" * 50)

    diff_methods = []
    diff_lines = []

    before_code = vuln_func_code.split("\n")
    after_code = non_vuln_func_code.split("\n")

    diff_lines = diff_merge(before_code, after_code)
    diff_methods.append("\n".join(diff_lines))

    # Rest of the prompt construction remains the same
    commit = "\n".join(diff_methods)
    evaluation_result_vuln = evaluation_agent.evaluate_analysis(
        cve_desc=item['cve_desc'],
        cwe_id=item['cwe'],
        commit_msg=item['vulnerability_fixing_commit_message'],
        commit=commit,
        rationale=debate_result_vuln["debate_history"][-2]['output'],
        is_vuln=True
    )

    parsed_eval = _extract_json_from_raw(str(evaluation_result_vuln['output']))
    if parsed_eval is not None:
        evaluation_result_vuln['output'] = parsed_eval
    else:
        print(f"  [WARN] EvaluationOracle output parse failed for vuln, raw: {str(evaluation_result_vuln['output'])[:100]}")

    print(f"Evaluation completed for {vuln_func_name}")
    print(f"Correctness: {evaluation_result_vuln.get('output',{}).get('prediction','UNKNOWN') if isinstance(evaluation_result_vuln.get('output'), dict) else 'PARSE_ERROR'}")
    print(f"rationale: {evaluation_result_vuln.get('output',{}).get('rationale','N/A') if isinstance(evaluation_result_vuln.get('output'), dict) else 'N/A'}")
    
    # Use debate's integrated decision (considers both Analyst + Architect)
    det_result = debate_result_vuln.get('is_vulnerable', True)
    
    return {
        "idx": item["idx"],
        "project": item["project"],
        "function_name": vuln_func_name,
        "debate_result": debate_result_vuln,
        "detection_result": det_result,
        "consensus_reached": debate_result_vuln['consensus_reached'],
        "evaluation_result": evaluation_result_vuln,
        "ground_truth": True
    }

def benign(non_vuln_func_name, item, react_agent, reflexion_agent, evaluation_agent):
    # Process Benign (non-vulnerable) function
    print(f"\n[BENIGN FUNCTION ANALYSIS - Process {os.getpid()}]")
    print(f"Function: {non_vuln_func_name}")
    print("-" * 50)
    
    @tool("get_callers")
    def get_callers_benign(function_name: str) -> str:
        """Returns a JSON list of functions that call the given function."""
        return tools.get_callers.invoke({"function_name": function_name, "caller_graph": item["non_vulnerable_caller_graph"]})
    
    @tool("get_callees") 
    def get_callees_benign(function_name: str) -> str:
        """Returns a JSON list of functions called by the given function."""
        return tools.get_callees.invoke({"function_name": function_name, "callee_graph": item["non_vulnerable_callee_graph"]})
    
    @tool("get_function_body")
    def get_function_body_benign(function_name: str) -> str:
        """Retrieves the body of a function as a string."""
        return tools.get_function_body.invoke({
            "function_name": function_name,
            "function_bodies": item["non_vulnerable_function_bodies"], 
            "project_url": item.get("project_url"),
            "commit_id": item.get("vulnerability_fixing_commit_id"),
            "file_name": item.get("file_name")
        })
    
    react_agent.set_tools([get_callers_benign, get_callees_benign, get_function_body_benign])
    
    # Conduct iterative debate between agents
    print("Starting iterative debate for benign function...")
    print("-" * 50)

    if item["non_vulnerable_function_body"][0:2] == 'c\n':
        non_vuln_func_code = item["non_vulnerable_function_body"][2:]
    elif item["non_vulnerable_function_body"][0:4] == 'cpp\n':
        non_vuln_func_code = item["non_vulnerable_function_body"][4:]
    else:
        non_vuln_func_code = item["non_vulnerable_function_body"]
    vuln_func_code = item["vulnerable_function_body"]
    
    debate_result_benign = iterative_debate(
        react_agent, reflexion_agent, 
        non_vuln_func_name, non_vuln_func_code, max_rounds=3
    )
    
    # EVALUATION STEP - Evaluate the analysis
    print(f"\n[EVALUATION STEP FOR {non_vuln_func_name}]")
    print("-" * 50)

    diff_methods = []
    diff_lines = []

    before_code = vuln_func_code.split("\n")
    after_code = non_vuln_func_code.split("\n")

    diff_lines = diff_merge(before_code, after_code)
    diff_methods.append("\n".join(diff_lines))

    # Rest of the prompt construction remains the same
    commit = "\n".join(diff_methods)
    evaluation_result_benign = evaluation_agent.evaluate_analysis(
        cve_desc=item['cve_desc'],
        cwe_id=item['cwe'],
        commit_msg=item['vulnerability_fixing_commit_message'],
        commit=commit,
        rationale=debate_result_benign["debate_history"][-2]['output'],
        is_vuln=False
    )

    parsed_eval_b = _extract_json_from_raw(str(evaluation_result_benign['output']))
    if parsed_eval_b is not None:
        evaluation_result_benign['output'] = parsed_eval_b
    else:
        print(f"  [WARN] EvaluationOracle output parse failed for benign, raw: {str(evaluation_result_benign['output'])[:100]}")

    print(f"Evaluation completed for {non_vuln_func_name}")
    print(f"Correctness: {evaluation_result_benign.get('output',{}).get('prediction','UNKNOWN') if isinstance(evaluation_result_benign.get('output'), dict) else 'PARSE_ERROR'}")
    print(f"rationale: {evaluation_result_benign.get('output',{}).get('rationale','N/A') if isinstance(evaluation_result_benign.get('output'), dict) else 'N/A'}")
    
    # Use debate's integrated decision (considers both Analyst + Architect)
    det_result = debate_result_benign.get('is_vulnerable', True)
    
    return {
        "idx": item["idx"],
        "project": item["project"],
        "function_name": non_vuln_func_name,
        "debate_result": debate_result_benign,
        "detection_result": det_result,
        "consensus_reached": debate_result_benign['consensus_reached'],
        "evaluation_result": evaluation_result_benign,
        "ground_truth": False
    }

def diff_merge(before_code, after_code):
    differ = difflib.Differ()
    diff_list = list(differ.compare(before_code, after_code))

    diff_lines = []
    for line in diff_list:
        if line.startswith("  "):
            diff_lines.append(line[2:])
        elif line.startswith("- "):
            diff_lines.append("-" + line[2:])
        elif line.startswith("+ "):
            diff_lines.append("+" + line[2:])

    return diff_lines

def process_item_pair(item_data):
    """
    Process a single item (both vulnerable and benign functions) in a separate process
    """
    item, model_name = item_data
    
    # Initialize agents with correct model for this process
    _react_agent = ReActAgent(model_name=model_name)
    _reflexion_agent = ReflexionAgent(model_name=model_name)
    _evaluation_agent = EvaluationAgent(model_name=model_name)
    
    print(f"\n{'='*80}")
    print(f"PROCESSING PAIR - Process {os.getpid()}")
    print(f"Project: {item['project']}, IDX: {item['idx']}")
    print(f"{'='*80}")
    
    
    try:
        non_vuln_func_list = list(item["non_vulnerable_function_bodies"].keys())
        vuln_func_list = list(item["vulnerable_function_bodies"].keys())
        
        non_vuln_func_name = non_vuln_func_list[0]
        vuln_func_name = vuln_func_list[0]
        
        # Process both vulnerable and benign functions
        vuln_result = vuln(vuln_func_name, item, _react_agent, _reflexion_agent, _evaluation_agent)
        benign_result = benign(non_vuln_func_name, item, _react_agent, _reflexion_agent, _evaluation_agent)
        
        return [vuln_result, benign_result]
        
    except Exception as e:
        print(f"Error processing item {item['idx']}: {e}")
        return None

def safe_write_results(results, output_path, lock):
    """
    Safely write results to file using a lock
    """
    with lock:
        with open(output_path, "w") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

def run_multi_agent_workflow(benchmark_path, limit=3, model_name="gpt-4o", num_processes=None):
    """
    Multi-agent workflow with parallel processing using multiprocessing Pool
    """
    
    # Determine number of processes
    if num_processes is None:
        num_processes = 1 #  mp.cpu_count() - 8  # Use at most 4 processes by default
    
    print(f"Using {num_processes} processes for parallel execution")
    
    output_path = f"results_{model_name}.json"
    
    # Load existing results
    if os.path.exists(output_path):
        with open(output_path, "r") as f:
            existing_results = json.load(f)
        exist_ids = set([r['idx'] for r in existing_results])
    else:
        existing_results = []
        exist_ids = set()
    
    # Prepare items to process
    items_to_process = []
    count = 0
    
    with open(benchmark_path, "r") as f:
        for line in f:
            item = json.loads(line)
            
            if item['idx'] in exist_ids:
                continue
                
            if count >= limit:
                break
                
            # Check if we have the required data
            if not item.get("non_vulnerable_function_bodies") or not item.get("vulnerable_function_bodies"):
                print(f"Skipping entry for {item.get('project', 'Unknown')} - missing function bodies")
                continue
                
            non_vuln_func_list = list(item["non_vulnerable_function_bodies"].keys())
            vuln_func_list = list(item["vulnerable_function_bodies"].keys())
            
            if not non_vuln_func_list or not vuln_func_list:
                print(f"Skipping entry for {item.get('project', 'Unknown')} - empty function lists")
                continue
            
            items_to_process.append((item, model_name))
            count += 1
    
    if not items_to_process:
        print("No items to process")
        return
    
    print(f"Processing {len(items_to_process)} item pairs using {num_processes} processes")
    
    # Create manager for shared results and lock
    with Manager() as manager:
        results = manager.list(existing_results)
        lock = manager.Lock()
        
        # Create process pool and execute
        with Pool(processes=num_processes) as pool:
            # Process items in parallel
            parallel_results = pool.map(process_item_pair, items_to_process)
            
            # Collect results
            final_results = list(existing_results)
            for result in parallel_results:
                if result is not None:
                    final_results.extend(result)
            
            # Write final results
            with open(output_path, "w") as f:
                json.dump(final_results, f, ensure_ascii=False, indent=2)
    
    print(f"Completed processing. Results saved to {output_path}")
    print(f"Total results: {len(final_results)}")

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Parallel Multi-Agent Vulnerability Analysi")
    parser.add_argument("--limit", type=int, default=9999999, help="Number of function pairs to analyze")
    parser.add_argument("--benchmark", type=str, default="evaluated_benchmark.jsonl", help="Path to benchmark file")
    parser.add_argument("--model", type=str, default="gpt-4o", help="Model to use")
    parser.add_argument("--processes", type=int, default=None, help="Number of parallel processes")
    
    args = parser.parse_args()
    
    print("Starting Parallel Multi-Agent Vulnerability Analysis Workflow")

    # Set multiprocessing start method (important for some systems)
    if hasattr(mp, 'set_start_method'):
        try:
            mp.set_start_method('spawn', force=True)
        except RuntimeError:
            pass  # Already set
    
    run_multi_agent_workflow(
        args.benchmark, 
        limit=args.limit, 
        model_name=args.model,
        num_processes=args.processes
    )