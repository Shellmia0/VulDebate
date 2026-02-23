from langchain_openai import ChatOpenAI, AzureChatOpenAI
import os
# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Set LangSmith keys
os.environ["LANGCHAIN_TRACING_V2"] = "false"

class ReflexionAgent:
    def __init__(self, model_name="gpt-4o"):
        """
        Initialize Reflexion Agent with OpenAI api
        
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
        
        prompt = """You are a senior security architect and a world-renowned expert in C/C++ vulnerabilities. Your role is to act as a neutral and objective Reflexion agent for the analysis provided by another analyst. Your goal is to either validate their findings or identify flaws in their reasoning.

- INPUT
You will receive the full analysis from another analyst, which includes:
1. The original function that was analyzed.
2. The complete Thought -> Action -> Observation trajectory of the analysis.
2. The final JSON assessment produced by the analyst.

- CRITIQUE CHECKLIST
If you agree, briefly state why the analyst's reasoning is sound.
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