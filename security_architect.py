from langchain_openai import ChatOpenAI, AzureChatOpenAI
import os
# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv(override=False)

# Set LangSmith keys
os.environ["LANGCHAIN_TRACING_V2"] = "false"

class SecurityArchitect:
    def __init__(self, model_name="gpt-4o"):
        """
        Initialize Security Architect agent
        
        Args:
            model_name: Model name (default: "gpt-4o")
        """

        self.llm = ChatOpenAI(
            model=model_name, 
            temperature=0,
            base_url=os.environ.get("OPENAI_BASE_URL", None)
        )

        self.tools = [] # Store tools, but ReflexionAgent doesn't use initialize_agent directly

    def set_tools(self, tools_list):
        self.tools = tools_list

    def reflect_on_analysis(self, function_code, react_output):

        print(f"\n[REFLEXION AGENT ANALYSIS]")
        
        prompt = """You are a senior security architect and a world-renowned expert in C/C++ vulnerabilities. Your role is to act as a **skeptical challenger** — a devil's advocate — for the analysis provided by another analyst. Your primary goal is to rigorously stress-test the analyst's conclusion, especially when they claim a vulnerability exists.

- INPUT
You will receive the full analysis from another analyst, which includes:
1. The original function that was analyzed.
2. The complete Thought -> Action -> Observation trajectory of the analysis.
3. The final JSON assessment produced by the analyst.

- CRITICAL REVIEW PRINCIPLES
1. **Challenge vulnerability claims aggressively.** LLMs have a systematic bias toward reporting vulnerabilities. Your job is to counteract this bias.
2. **Check reachability:** Is the reported vulnerability actually reachable through real calling paths? Did the analyst check callers to verify that unsafe inputs can actually reach this function?
3. **Check preconditions:** Does the vulnerability require unrealistic preconditions (e.g., NULL passed to an internal function, integer overflow on a value that is always small)?
4. **Check upstream guards:** Do callers already validate inputs before calling this function? If so, the "vulnerability" is not exploitable.
5. **Do NOT rubber-stamp.** If the analyst claims "vulnerable," you must actively look for reasons it might be safe before agreeing. Only agree if the evidence is truly compelling.

- CRITIQUE CHECKLIST
If you agree, you must explain what specific evidence convinced you that the vulnerability is real AND reachable.
If you disagree, you must provide a detailed counterargument. Your counterargument must:
1. Clearly state the flaw in the analyst's reasoning.
2. Cite specific evidence from the code, the analyst's trace, or established security principles (e.g., CWE definitions).
3. Explicitly state what the analyst must do to address your concerns and reach a consensus.

- OUTPUT FORMAT
You MUST output your critique in a single JSON block. The JSON object must conform to the following schema:
```json
{
  "agreement": "<boolean, true if you fully agree with the analyst's conclusion and reasoning, false otherwise>",
  "feedback": "<string, a detailed natural language explanation of your critique. If agreement is false, explain exactly what is wrong with the analysis and provide specific, policy-level advice on how to improve it. If agreement is true, state that the analysis is sound and complete.>"
}
```"""+f"""

- CUCURRENT TASK
Original Function to Analyze:
{function_code}

Analyst's Full Analysis to Review:
{react_output['trajectory']}"""

        print(f"{'='*60}")
        response = self.llm.invoke(prompt)

        return {"input": prompt, "output": response.content.strip()}