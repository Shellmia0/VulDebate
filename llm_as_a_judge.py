import json
import os
import difflib
from langchain_openai import ChatOpenAI, AzureChatOpenAI
import os
  
from dotenv import load_dotenv
load_dotenv()

class EvaluationAgent:
    def __init__(self):

      self.llm = ChatOpenAI(model="gpt-4o", temperature=0)

    def evaluate_analysis(self, cve_desc, cwe_id, 
                         commit_msg, commit, rationale, is_vuln):
        
        if is_vuln:
            ground_truth = {
                "is_vulnerable": is_vuln,
                "cwe_types": cwe_id,
                "cve_description": cve_desc,
                "commit_message": commit_msg,
                "patch": commit
            }
        else:
            ground_truth = {
                "is_vulnerable": is_vuln,
                "cwe_types": "N/A",
                "cve_description": cve_desc,
                "commit_message": commit_msg,
                "patch": commit
            }
        ground_truth = json.dumps(ground_truth, ensure_ascii=False, indent=2)

        print(f"\n[EVALUATION AGENT]")
        print(f"{'='*60}")

        instruction = ""
        if is_vuln:
            instruction = f"""Please note that the final analysis produced by the agent is generated based on the vulnerable version of the code, not the patched one.
If the agent identifies the ground truth vulnerability in the vulnerable code, regardless of whether it also identifies other vulnerabilities, return MATCH.
If the agent does not identify the ground truth vulnerability in the vulnerable code, even if it identifies other vulnerabilities, return MISMATCH.
    """
        else:
            instruction = f"""Please note that the final analysis produced by the agent is generated based on the patched version of the code, not the vulnerable one.
If the agent believes that the ground truth vulnerability, which has actually been fixed, still exists in the patched code, return FALSE_ALARM.
If the agent does not identify the ground truth vulnerability in the patched code, even if it identifies other vulnerabilities, return MATCH.
    """

        prompt = """You are an Evaluation Oracle, an automated system for judging the correctness of a vulnerability detection agent's prediction. Your goal is to compare an agent's final vulnerability analysis against a provided ground truth. You will determine if the agent's prediction is correct and provide a rationale for your judgment.

- INPUTS
You will be given two JSON objects:
1. Agent Output: The final analysis produced by the agent.
2. Ground Truth: The ground truth information."""+f"""

- EVALUATION CRITERIA
{instruction}"""+"""

- OUTPUT FORMAT
You MUST output your evaluation in a single JSON block. The JSON object must conform to the following schema:
```json
{
    "prediction": "<string, 'MATCH', "MISMATCH, or 'FALSE_ALARM'>",
    "rationale": "<string, A brief explanation for your judgment. For example, 'The agent correctly identified the function as vulnerable, but misclassified the vulnerability type. The agent identified a CWE-120, but the ground truth is CWE-787.' or 'The agent correctly identified the function as non-vulnerable and provided a sound explanation.'>"
}
```"""+f"""

- CURRENT TASK
Agent Output:
```json
{rationale}
```

Ground Truth:
```json
{ground_truth}
```"""

        response = self.llm.invoke(prompt)
    
        return {"input": prompt, "output": response.content.strip()}
    
def load_jsonl_file(filename):
   with open(filename, 'r') as f:
       data = []
       for line in f:
           # Convert each line into a JSON object
           data_object = json.loads(line)
           data.append(data_object)
   return data

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


def test():
    with open("results_gpt-4o.json", 'r') as f:
        outputs = json.load(f)
        
    final = load_jsonl_file("evaluated_benchmark.jsonl")
    final = {d['idx']: d for d in final}
        
    agent = EvaluationAgent()

    if os.path.exists(f"evaluation_results.json"):
        with open(f"evaluation_results.json", 'r') as f:
            results = json.load(f)
    else:
        results = []

    for d in outputs:
        idx = d['idx']
        item = final[idx]
        result = {'idx': d['idx'], 'ground_truth': d['ground_truth']}
        if item["non_vulnerable_function_body"][0:2] == 'c\n':
            non_vuln_func_code = item["non_vulnerable_function_body"][2:]
        elif item["non_vulnerable_function_body"][0:4] == 'cpp\n':
            non_vuln_func_code = item["non_vulnerable_function_body"][4:]
        else:
            non_vuln_func_code = item["non_vulnerable_function_body"]
        vuln_func_code = item["vulnerable_function_body"]
        
        diff_methods = []
        diff_lines = []

        before_code = vuln_func_code.split("\n")
        after_code = non_vuln_func_code.split("\n")

        diff_lines = diff_merge(before_code, after_code)
        diff_methods.append("\n".join(diff_lines))

        # Rest of the prompt construction remains the same
        commit = "\n".join(diff_methods)
        if round == 2:
            try:
                rationale = d['debate_result']['debate_history'][round]['output']
            except:
                rationale = d['debate_result']['debate_history'][round-2]['output']
        evaluation_result = agent.evaluate_analysis(
            cve_desc=item['cve_desc'],
            cwe_id=item['cwe'],
            commit_msg=item['vulnerability_fixing_commit_message'],
            commit=commit,
            rationale=rationale,
            is_vuln=d['ground_truth']
        )
        result['evaluation'] = evaluation_result
        results.append(result)
        with open(f"evaluation_results.json", 'w') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

test()