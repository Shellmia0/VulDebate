from langchain_openai import ChatOpenAI, AzureChatOpenAI

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv(override=False)

import os

# Set LangSmith keys
os.environ["LANGCHAIN_TRACING_V2"] = "false"

class EvaluationOracle:
    def __init__(self, model_name="gpt-4o"):

        self.llm = ChatOpenAI(
            model=model_name, 
            temperature=0,
            base_url=os.environ.get("OPENAI_BASE_URL", None)
        )

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