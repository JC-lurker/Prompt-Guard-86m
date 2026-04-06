"""
Prompt Guard – mitmproxy Addon
===============================
A mitmproxy addon that selectively scans AI API traffic through Meta's
Prompt Guard 86M model.  Non-AI traffic is passed through untouched.

Usage:
  mitmdump -s guard.py --listen-port 8080
  mitmweb  -s guard.py --listen-port 8080   (with web UI)
"""

import io
import json
import os
import re
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import torch
import yaml
from mitmproxy import ctx, http
from torch.nn.functional import softmax
from transformers import AutoModelForSequenceClassification, AutoTokenizer

# Force unbuffered output for Docker logs
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, write_through=True)
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, write_through=True)


# ── Configuration ───────────────────────────────────────────────────────
CONFIG_PATH = os.environ.get("PROMPT_GUARD_CONFIG", "/root/mitmproxy/guard.yaml")

if not os.path.isfile(CONFIG_PATH):
    FALLBACK_CONFIG = "guard.yaml"
    if os.path.isfile(FALLBACK_CONFIG):
        CONFIG_PATH = FALLBACK_CONFIG
    else:
        raise RuntimeError(
            f"Config file not found in {CONFIG_PATH} or {FALLBACK_CONFIG}"
        )

print(f"Loading configuration from: {CONFIG_PATH}")
with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

model_config = config.get("model", {})
server_config = config.get("server", {})
logging_config = config.get("logging", {})
scanning_config = config.get("scanning", {})
request_config = config.get("request", {})
response_config = config.get("response", {})
proxy_config = config.get("proxy", {})

# Model Config
MODEL_ID = model_config.get("id", "meta-llama/Prompt-Guard-86M")
HF_TOKEN_ENV = model_config.get("token_env", "HUGGINGFACE_TOKEN")
HF_TOKEN = os.environ.get(HF_TOKEN_ENV)
if not HF_TOKEN:
    raise RuntimeError(
        f"{HF_TOKEN_ENV} environment variable is required to load the model."
    )

# Scanning Config
PROMPT_THRESHOLD = scanning_config.get("prompt_threshold", 0.5)
DOCUMENT_THRESHOLD = scanning_config.get("document_threshold", 0.3)
MAX_LENGTH = scanning_config.get("max_length", 512)
MAX_EXTRACTED_TEXT_LENGTH = scanning_config.get("max_extracted_text_length", 3000)

# Logging Config
LOG_REQUESTS = logging_config.get("log_requests", True)
LOG_BLOCKS = logging_config.get("log_blocks", True)
LOG_SAFE_REQUESTS = logging_config.get("log_safe_requests", False)
LOG_PASSTHROUGH = logging_config.get("log_passthrough", False)

# Proxy/Policy Config
SCAN_REQUESTS = request_config.get("scan_requests", True)
SCAN_ROLES = request_config.get("scan_roles", ["user", "tool"])
EXTRACT_FIELDS = request_config.get("extract_fields", ["text", "prompt", "messages", "input", "query"])

# AI API paths — match by substring
DEFAULT_AI_PATHS = [
    "chat/completions",
    "completions",
    "messages",
    "embeddings",
    "images/generations",
    "audio/transcriptions",
    "v1/chat",
    "api/openai",
    "api/chat",
]
AI_PATHS = proxy_config.get("ai_paths", DEFAULT_AI_PATHS)

# Window size for streaming scanning
SCAN_WINDOW_SIZE = scanning_config.get("scan_window_size", 200)


# ── Utility Functions ───────────────────────────────────────────────────
def log(prefix: str, msg: str, extra: Dict[str, Any] = None):
    """Print formatted logs to the mitmproxy console and UI."""
    timestamp = time.strftime("%H:%M:%S")
    log_msg = f"[{prefix}] {msg}"
    if extra:
        log_msg += f" {json.dumps(extra, ensure_ascii=False)[:1500]}"

    # Send to Terminal (Standard Out)
    print(f"[{timestamp}] {log_msg}")

    # Send to Mitmweb UI (Event Log)
    try:
        if prefix in ["ERROR", "BLOCKED_REQUEST", "BLOCKED_RESPONSE", "KILL_STREAM"]:
            ctx.log.warn(log_msg)
        else:
            ctx.log.info(log_msg)
    except Exception:
        pass  # ctx may not be ready during startup


def is_ai_path(path: str) -> bool:
    """Check if the request path matches a known AI API endpoint."""
    path_lower = path.lower().split("?")[0]
    for pattern in AI_PATHS:
        if pattern in path_lower:
            return True
    return False


def extract_text_from_value(value: Any) -> str:
    """Recursively extract text strings from a JSON value."""
    if isinstance(value, str):
        return value.strip()
    elif isinstance(value, list):
        return " ".join(extract_text_from_value(v) for v in value)
    elif isinstance(value, dict):
        parts = []
        for key in ["content", "text", "data"]:
            if key in value:
                parts.append(extract_text_from_value(value[key]))
        return " ".join(parts)
    return ""


def extract_scannable_text(body: Any) -> str:
    """
    Role-aware smart extractor — surgically targets attack vectors.
    Uses the configured `scan_roles` from guard.yaml to determine which 
    parts of the message history to evaluate (typically just 'user' and 'tool').
    """
    if not isinstance(body, dict):
        return ""

    messages = body.get("messages", [])
    if not messages:
        # Non-chat format: scan fields from config
        parts = []
        for field in EXTRACT_FIELDS:
            val = body.get(field, "")
            if isinstance(val, str) and val.strip():
                parts.append(val)
        return " ".join(parts)[:MAX_EXTRACTED_TEXT_LENGTH]

    # We will ONLY collect the specific attack vectors
    attack_vectors = []
    
    # Process newest first
    for msg in reversed(messages):
        role = msg.get("role", "")
        content = msg.get("content", "")
        text = extract_text_from_value(content)
        
        if not text:
            continue

        # Extract only the roles explicitly allowed in the config
        if role in SCAN_ROLES:
            attack_vectors.append(f"[{role.upper()}] {text}")
                
        # Fallback: Even if role isn't targeted, if it contains tool-like XML tags, grab it.
        # This catches weird abstractions where tools write into the system/assistant stream.
        elif "<crawlResults>" in text or "<page url=" in text:
            attack_vectors.append(f"[EXTERNAL_DATA] {text}")

    # Reverse back so the text reads chronologically
    attack_vectors.reverse()
    
    joined = "\n\n".join(attack_vectors)
    
    # If it's still too large, keep the END of the string (newest content)
    if len(joined) > MAX_EXTRACTED_TEXT_LENGTH:
        return joined[-MAX_EXTRACTED_TEXT_LENGTH:]
    
    return joined


# ── Classification ──────────────────────────────────────────────────────
SCAN_LOCK = threading.Lock()


def classify_text(text: str) -> Dict[str, float]:
    """Run Prompt Guard model on text. Returns scores dict."""
    if not text.strip():
        return {"benign": 1.0, "injection": 0.0, "jailbreak": 0.0}

    with SCAN_LOCK:
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=MAX_LENGTH)
        with torch.no_grad():
            logits = model(**inputs).logits
        probs = softmax(logits, dim=-1)[0].tolist()

    return {"benign": probs[0], "injection": probs[1], "jailbreak": probs[2]}


def check_request_blocked(text: str) -> Tuple[bool, Dict[str, float]]:
    """Check if request text should be blocked. Checks both jailbreak AND injection."""
    scores = classify_text(text)
    # Block if jailbreak OR injection is above threshold
    # Requests come from the user but may contain fetched/external content (indirect injection)
    jailbreak_blocked = scores["jailbreak"] >= PROMPT_THRESHOLD
    injection_blocked = scores["injection"] >= DOCUMENT_THRESHOLD  # Use lower doc threshold for injections in context
    blocked = jailbreak_blocked or injection_blocked
    return (blocked, scores)


BLOCKED_RESPONSE_JSON = {
    "error": {
        "message": "This request was blocked by the Prompt Guard firewall.",
        "type": "prompt_guard_block",
        "code": "content_blocked",
    }
}


# ── Load Model ──────────────────────────────────────────────────────────
if SCAN_REQUESTS:
    print("Loading Prompt Guard model... this may take a moment.")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, token=HF_TOKEN)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID, token=HF_TOKEN)
    model.eval()
    print("Prompt Guard model loaded successfully.")
else:
    tokenizer = None
    model = None
    print("Scanning disabled — model not loaded (passthrough mode).")



# ── Stream Buffer Storage (keyed by flow.id) ────────────────────────────
_stream_buffers: Dict[str, dict] = {}


# ── mitmproxy Addon ─────────────────────────────────────────────────────
class PromptGuardAddon:
    def load(self, loader):
        print("")
        print("╔══════════════════════════════════════════════════════════╗")
        print("║          Prompt Guard Proxy  (mitmproxy)                ║")
        print("╠══════════════════════════════════════════════════════════╣")
        print(f"║  Model:          {MODEL_ID:<39s} ║")
        print(f"║  Scan requests:  {'ON' if SCAN_REQUESTS else 'OFF':<39s}║")
        print(f"║  Stream window:  {str(SCAN_WINDOW_SIZE) + ' chars':<39s}║")
        print(f"║  Scan roles:     {', '.join(SCAN_ROLES):<39s}║")
        print(f"║  Scan paths:     {str(len(AI_PATHS)) + ' AI path patterns':<39s}║")
        print("╚══════════════════════════════════════════════════════════╝")
        print("")

    # ── Request Scanning ────────────────────────────────────────────
    def request(self, flow: http.HTTPFlow):
        hostname = flow.request.pretty_host
        path = flow.request.path

        if not is_ai_path(path):
            return

        log("REQUEST", f"{flow.request.method} {hostname}{path}")

        if not SCAN_REQUESTS:
            return

        body = flow.request.get_content()
        if not body:
            return

        try:
            body_json = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return

        text = extract_scannable_text(body_json)
        if not text:
            return

        blocked, scores = check_request_blocked(text)
        log("SCAN_REQ", f"Scanned request to {hostname}", {
            "jailbreak": f"{scores['jailbreak']:.4f}",
            "injection": f"{scores['injection']:.4f}",
            "blocked": blocked,
            "text_len": len(text),
        })

        if blocked:
            log("BLOCKED_REQUEST", f"Request to {hostname} BLOCKED", {"scores": scores, "preview": text[:100]})
            block_body = {**BLOCKED_RESPONSE_JSON}
            block_body["error"]["debug_scores"] = scores
            flow.response = http.Response.make(
                403, json.dumps(block_body), {"Content-Type": "application/json"}
            )

    # ── SSE Streaming: Enable + Setup Window Scanner ────────────────
    def responseheaders(self, flow: http.HTTPFlow):
        """Enable streaming for SSE responses and set up sliding-window scan."""
        if not is_ai_path(flow.request.path):
            return

        content_type = flow.response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            flow.response.stream = True
            _stream_buffers[flow.id] = {"text": "", "last_scan_len": 0}
            log("STREAM", f"SSE streaming + window scan enabled → {flow.request.path}")

    # ── Sliding-Window Stream Scanner ───────────────────────────────
    def response(self, flow: http.HTTPFlow):
        """Scan streamed response chunks with a sliding window."""
        if flow.id not in _stream_buffers:
            return

        buf = _stream_buffers[flow.id]
        chunk = flow.response.get_content()
        if chunk:
            try:
                buf["text"] += chunk.decode("utf-8", errors="replace")
            except AttributeError:
                buf["text"] += str(chunk)

        # Scan every SCAN_WINDOW_SIZE characters
        if len(buf["text"]) - buf["last_scan_len"] > SCAN_WINDOW_SIZE:
            text = _extract_stream_content(buf["text"])
            if text:
                blocked, scores = check_request_blocked(text)
                buf["last_scan_len"] = len(buf["text"])
                log("SCAN_STREAM", f"Window scan ({len(text)} chars)", {
                    "injection": f"{scores['injection']:.4f}",
                    "jailbreak": f"{scores['jailbreak']:.4f}",
                    "blocked": blocked,
                })
                if blocked:
                    log("KILL_STREAM", f"Injection detected mid-stream! Killing connection.")
                    flow.kill()
                    _stream_buffers.pop(flow.id, None)
                    return

        # Clean up when stream is done
        if flow.response and not flow.response.stream:
            _stream_buffers.pop(flow.id, None)


def _extract_stream_content(full_buffer: str) -> str:
    """Extract text content from SSE stream chunks (OpenAI/Anthropic delta format)."""
    extracted = []
    matches = re.findall(r'"content"\s*:\s*"([^"]*)"', full_buffer)
    for m in matches:
        extracted.append(m.replace('\\n', '\n').replace('\\"', '"'))
    return "".join(extracted)


# Register the addon — mitmproxy auto-discovers this list
addons = [PromptGuardAddon()]
