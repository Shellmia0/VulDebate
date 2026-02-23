# tools.py
from langchain_core.tools import tool
import json
import requests
import re

@tool("get_callers")
def get_callers(function_name: str, caller_graph: dict = None) -> str:
    """Returns a JSON list of functions that call the given function."""
    if caller_graph:
        result = caller_graph.get(function_name, [])
        return json.dumps(result)
    return json.dumps([])

@tool("get_callees")
def get_callees(function_name: str, callee_graph: dict = None) -> str:
    """Returns a JSON list of functions called by the given function."""
    if callee_graph:
        result = callee_graph.get(function_name, [])
        return json.dumps(result)
    return json.dumps([])

# GitHub fetching logic

GITHUB_MIRRORS = [
    "https://ghfast.top/https://raw.githubusercontent.com/{owner_repo}/{commit_id}/{file_name}",
    "https://raw.githubusercontent.com/{owner_repo}/{commit_id}/{file_name}",
]

def get_github_raw_url(project_url, commit_id, file_name):
    owner_repo = '/'.join(project_url.rstrip('/').split('/')[-2:])
    return owner_repo

def fetch_function_body_from_github(project_url, commit_id, file_name, function_name):
    owner_repo = get_github_raw_url(project_url, commit_id, file_name)
    
    for mirror_template in GITHUB_MIRRORS:
        url = mirror_template.format(owner_repo=owner_repo, commit_id=commit_id, file_name=file_name)
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                code = resp.text
                pattern = re.compile(rf"{re.escape(function_name)}\s*\([^)]*\)\s*\{{.*?\n\}}", re.DOTALL)
                match = pattern.search(code)
                return (match.group(0) if match else None), code
        except Exception:
            continue
    return None, None
    if resp.status_code != 200:
        return None, None
    code = resp.text
    pattern = re.compile(rf"{function_name}\s*\([^)]*\)\s*\{{.*?\n\}}", re.DOTALL)
    match = pattern.search(code)
    return (match.group(0) if match else None), code

@tool("get_function_body")
def get_function_body(function_name: str, function_bodies: dict = None, project_url: str = None, commit_id: str = None, file_name: str = None) -> str:
    """Retrieves the body of a function as a string. Tries function_bodies first, then GitHub if info is provided."""
    if function_bodies:
        body = str(function_bodies.get(function_name, ''))
        if body:
            return body
    
    if project_url and commit_id and file_name:
        body, _ = fetch_function_body_from_github(project_url, commit_id, file_name, function_name)
        if body:
            return body
    
    return ''

# These will be populated with partial functions in main.py
REACT_TOOLS = []
REFLEXION_TOOLS = []

