from langchain_openai import ChatOpenAI, AzureChatOpenAI
from langchain.agents import initialize_agent, AgentType
import os

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Set LangSmith keys
os.environ["LANGCHAIN_TRACING_V2"] = "false"

class ReActAgent:
    def __init__(self, model_name="gpt-4o"):
        """
        Initialize ReAct Agent with OpenAI api
        
        Args:
            model_name: Model name (default: "gpt-4o")
        """

        self.llm = ChatOpenAI(
            model=model_name, 
            temperature=0,
            base_url=os.environ.get("OPENAI_BASE_URL", None)
        )

        
        self.tools = []
        self.agent = None

    def set_tools(self, tools_list):
        """Set the tools for this agent and reinitialize the agent."""
        self.tools = tools_list
        self.agent = initialize_agent(
            tools=self.tools,
            llm=self.llm,
            agent_type=AgentType.CHAT_ZERO_SHOT_REACT_DESCRIPTION,
            verbose=True,
            handle_parsing_errors=True,
            max_iterations=25,
            max_execution_time=120,
            return_intermediate_steps=True
        )

    def predict(self, function_code, history=[]):
        if not self.agent:
            raise ValueError("Tools must be set before calling predict. Use set_tools() first.")
        
        history = [{"round": h['round'], "agent": h['agent'], "output": h['output']} for h in history] if history != [] else "None"
        prompt = """You are an expert cybersecurity researcher specializing in static code analysis of C/C++ programs. Your task is to meticulously analyze a given function for security vulnerabilities. Your goal is to determine if the provided C/C++ function is vulnerable.

- CONSTRAINTS
1. You can ONLY use the tools provided in the 'TOOLS' section. Do not hallucinate or assume the existence of other tools.
2. Your reasoning (in the 'Thought' section) must be clear, explicit, and justify every action you take.
3. If you receive a 'Critique' from the Adjudicator, you must start a new analysis that directly addresses the feedback. Incorporate the critique into your reasoning.

- TOOLS
You have access to the following tools for code analysis:
1. get_function_body: Retrieves the full source code for a given function name
2. get_callers: Finds all functions that directly call the specified function
3. get_callees: Finds all functions that are directly called by the specified function

- OUTPUT FORMAT
Thought: you should always think about what to do
Action: the action to take, should be one of [get_function_body, get_callers, get_callees]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: output your final answer in a single JSON block. The JSON object must conform to the following schema:
```json
{
  "is_vulnerable": "<boolean>",
  "vulnerability_type": "<string>",
  "cwe_id": "<string>",
  "explanation": "<string, A detailed, step-by-step explanation of the vulnerability and its root cause. If not vulnerable, explain why the code is safe.>"
}
```"""+f"""

- CURRENT TASK
Function to Analyze:
{function_code}

History of Previous Attempts and Corresponding Adjudicator's Critiques (if any):
{history}"""
        response = self.agent.invoke(prompt)
        return response

     