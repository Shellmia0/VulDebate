# VulDebate

**Multi-Agent Debate-Driven Vulnerability Detection**

VulDebate is a multi-agent framework for detecting vulnerabilities in C/C++ source code through structured debate. It leverages two specialized LLM agents — a **Vulnerability Analyst** (ReAct) and a **Security Architect** (Reflexion) — that engage in adversarial debate rounds to produce high-confidence vulnerability assessments with reduced false positives.

## Architecture

```
                    ┌─────────────────────┐
                    │    Function Code     │
                    └─────────┬───────────┘
                              ▼
               ┌──────────────────────────────┐
               │   Vulnerability Analyst       │
               │   (ReAct Agent + Tools)       │
               │   - get_function_body         │
               │   - get_callers               │
               │   - get_callees               │
               └──────────────┬───────────────┘
                              ▼
               ┌──────────────────────────────┐
               │   Security Architect          │
               │   (Reflexion Critic)          │
               │   - Challenges VA findings    │
               │   - Checks reachability       │
               │   - Verifies upstream guards  │
               └──────────────┬───────────────┘
                              ▼
                    ┌─────────────────────┐
                    │  Debate Rounds (1-3) │
                    │  Until consensus     │
                    └─────────┬───────────┘
                              ▼
                    ┌─────────────────────┐
                    │   Final Assessment   │
                    │   (JSON verdict)     │
                    └─────────────────────┘
```

- **Vulnerability Analyst**: Uses a ReAct loop with code analysis tools to investigate the target function, trace callers/callees, and form an initial vulnerability assessment.
- **Security Architect**: Acts as a skeptical reviewer using Reflexion, challenging the analyst's conclusions to reduce false positives by checking reachability, preconditions, and upstream guards.
- **Debate Loop**: The two agents iterate for up to 3 rounds until they reach consensus.

## Installation

```bash
# Clone the repository
git clone https://github.com/Shellmia0/VulDebate.git
cd VulDebate

# Create conda environment
conda env create -f environment.yml
conda activate mavul
```

## Environment Variables

Set the API keys for the LLM providers you plan to use:

```bash
export DASHSCOPE_API_KEY="your-dashscope-key"
export GOOGLE_API_KEY="your-google-api-key"
export OPENROUTER_API_KEY="your-openrouter-api-key"
```

## Usage

```bash
# Run multi-agent vulnerability detection
python main.py --model qwen3.5-plus --input evaluated_benchmark.jsonl
```

### Key Files

| File | Description |
|------|-------------|
| `main.py` | Main entry point and debate orchestration |
| `vulnerability_analyst.py` | ReAct-based Vulnerability Analyst agent |
| `security_architect.py` | Reflexion-based Security Architect agent |
| `react_agent.py` | ReAct agent implementation |
| `reflexion_agent.py` | Reflexion agent implementation |
| `tools.py` | Code analysis tools (get_function_body, get_callers, get_callees) |
| `evaluation_agent.py` | Evaluation pipeline |
| `evaluation_oracle.py` | Oracle-based evaluation |
| `llm_as_a_judge.py` | LLM-as-a-Judge evaluation method |
| `api_config.py` | Multi-provider API routing configuration |
| `evaluated_benchmark.jsonl` | Benchmark dataset for evaluation |

## Benchmark

The included `evaluated_benchmark.jsonl` contains C/C++ functions from real-world projects, labeled with ground-truth vulnerability information for evaluation purposes.

## License

MIT
