"""API provider routing by model name."""
import os

PROVIDERS = {
    "dashscope": {
        "api_key": os.environ.get("DASHSCOPE_API_KEY", ""),
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "models": [
            "qwen3-235b-a22b",
            "qwen3.5-397b-a17b",
            "qwen3.5-plus",
            "qwq-plus",
            "qwen-plus",
            "deepseek-r1",
            "deepseek-v3",
            "MiniMax/MiniMax-M2.5",
        ],
    },
    "google": {
        "api_key": os.environ.get("GOOGLE_API_KEY", ""),
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "models": [
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            "gemini-2.0-flash",
        ],
    },
    "openrouter": {
        "api_key": os.environ.get("OPENROUTER_API_KEY", ""),
        "base_url": "https://openrouter.ai/api/v1",
        "models": [
            "google/gemini-3-pro-preview",
            "google/gemini-2.5-pro",
        ],
    },
}


def get_api_config(model_name: str) -> dict:
    """Return {"api_key": ..., "base_url": ...} for the given model.
    
    Raises ValueError if model is not recognized.
    """
    for provider, cfg in PROVIDERS.items():
        if model_name in cfg["models"]:
            return {
                "api_key": cfg["api_key"],
                "base_url": cfg["base_url"],
                "provider": provider,
            }
    # Fallback: if model contains '/' assume OpenRouter
    if "/" in model_name:
        cfg = PROVIDERS["openrouter"]
        return {"api_key": cfg["api_key"], "base_url": cfg["base_url"], "provider": "openrouter"}
    # Default to DashScope
    cfg = PROVIDERS["dashscope"]
    return {"api_key": cfg["api_key"], "base_url": cfg["base_url"], "provider": "dashscope"}


def apply_env(model_name: str):
    """Set OPENAI_API_KEY and OPENAI_BASE_URL env vars for the given model."""
    cfg = get_api_config(model_name)
    os.environ["OPENAI_API_KEY"] = cfg["api_key"]
    os.environ["OPENAI_BASE_URL"] = cfg["base_url"]
    print(f"[api_config] {model_name} → {cfg['provider']} ({cfg['base_url'][:40]}...)")
    return cfg
