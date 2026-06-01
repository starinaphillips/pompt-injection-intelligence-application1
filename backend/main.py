from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import torch
import joblib
import os
import re
import requests
#import easyocr

from bs4 import BeautifulSoup

from collections import Counter

from transformers import AutoTokenizer, AutoModelForSequenceClassification

from backend.llm_service import ask_llm
torch.set_grad_enabled(False)
# ==================================================
# FASTAPI
# ==================================================

app = FastAPI(title="Prompt Guard API")


# ==================================================
# CORS
# ==================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================================================
# PATHS
# ==================================================

BASE_DIR = os.path.dirname(__file__)

ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))

MODEL_PATH = os.path.join(ROOT_DIR, "distilbert_model")

ENCODER_PATH = os.path.join(ROOT_DIR, "label_encoder.pkl")
# ==================================================
# DEVICE
# ==================================================
device = torch.device("cpu")
#reader = easyocr.Reader(["en"])

print("\n================================================")

if torch.cuda.is_available():

    print("GPU Detected")

    print("GPU Name:", torch.cuda.get_device_name(0))

else:

    print("Using CPU")

print("Using Device:", device)

print("================================================")


# ==================================================
# LOAD TRANSFORMER MODEL
# ==================================================

print("\nLoading Tokenizer...")

tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, local_files_only=True)

print("Loading Model...")

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_PATH, local_files_only=True
)

model.to(device)

model.eval()

print("Loading Label Encoder...")

encoder = joblib.load(ENCODER_PATH)

print("\nLoaded Classes:")

for idx, cls in enumerate(encoder.classes_):

    print(f"{idx} -> {cls}")


#
def detect_prompt_attack(prompt):

    inputs = tokenizer(
        prompt, return_tensors="pt", truncation=True, padding=True, max_length=256
    )

    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():

        outputs = model(**inputs)

    probs = torch.nn.functional.softmax(outputs.logits, dim=-1)

    confidence = float(torch.max(probs))

    pred = torch.argmax(probs).item()

    attack_type = encoder.inverse_transform([pred])[0]

    return {"attack_type": attack_type, "confidence": round(confidence, 4)}


# ==================================================
# MEMORY STATS
# ==================================================

total_scans = 0

attacks = 0

safe = 0

attack_categories = Counter()


# ==================================================
# REQUEST MODEL
# ==================================================


class PromptRequest(BaseModel):

    prompt: str


# ==================================================
# SIMPLE USER FRIENDLY EXPLANATIONS
# ==================================================


def explain_attack(label: str) -> str:

    mapping = {
        "safe": "This prompt appears safe and does not contain suspicious instructions.",
        "instruction_override": "This prompt attempts to make the AI ignore previous instructions or safety rules.",
        "prompt_extraction": "This prompt attempts to access hidden system prompts or confidential information.",
        "persona_hijacking": "This prompt attempts to force the AI to behave as another person or role.",
        "context_manipulation": "This prompt attempts to manipulate the AI behavior or bypass protections.",
        "indirect_injection": "This prompt contains hidden or indirect instructions intended to manipulate the AI.",
        "obfuscated_attack": "This prompt hides malicious instructions using altered or disguised text patterns.",
        "multi_step_attack": "This prompt uses multiple steps to gradually bypass AI safety protections.",
        "unknown_attack": "Unknown suspicious behavior detected.",
    }

    return mapping.get(label, "Potential malicious behavior detected.")


# ==================================================
# SANITIZATION
# ==================================================


def sanitize_prompt(text: str):

    patterns = [
        r"ignore previous instructions",
        r"reveal system prompt",
        r"developer mode",
        r"disable safety filters",
        r"pretend you are .*",
        r"act as .*",
    ]

    cleaned = text

    for p in patterns:

        cleaned = re.sub(p, "[REMOVED]", cleaned, flags=re.IGNORECASE)

    return re.sub(r"\s+", " ", cleaned).strip()


# ==================================================
# ROOT
# ==================================================


@app.get("/")
def root():

    return {"message": "Prompt Guard API Running"}


# ==================================================
# STATS
# ==================================================


@app.get("/stats")
def get_stats():

    return {
        "total_scans": total_scans,
        "attacks": attacks,
        "safe": safe,
        "attack_categories": dict(attack_categories),
    }


# ==================================================
# website detection endpoint
# ==================================================
@app.post("/scan-website")
def scan_website(data: dict):

    try:

        url = data["url"]

        response = requests.get(url)

        soup = BeautifulSoup(response.text, "html.parser")

        website_text = soup.get_text()

        result = detect_prompt_attack(website_text)

        return {"success": True, "result": result}

    except Exception as e:

        return {"success": False, "error": str(e)}


# ==============================================


#@app.post("/scan-image")
def scan_image(data: dict):

    try:

        image_path = data["path"]

        result_text = reader.readtext(image_path, detail=0)

        extracted_text = " ".join(result_text)

        result = detect_prompt_attack(extracted_text)

        return {"success": True, "extracted_text": extracted_text, "result": result}

    except Exception as e:

        return {"success": False, "error": str(e)}


# ==================================================
# SECURE CHAT
# ==================================================


@app.post("/secure-chat")
def secure_chat(data: PromptRequest):

    global total_scans
    global attacks
    global safe

    prompt = data.prompt

    total_scans += 1

    # ==============================================
    # TOKENIZE INPUT
    # ==============================================

    inputs = tokenizer(
        prompt, return_tensors="pt", truncation=True, padding=True, max_length=256
    )

    # MOVE TO GPU / CPU

    inputs = {key: value.to(device) for key, value in inputs.items()}

    # ==============================================
    # MODEL PREDICTION
    # ==============================================

    with torch.no_grad():

        outputs = model(**inputs)

    probs = torch.nn.functional.softmax(outputs.logits, dim=-1)

    confidence = float(torch.max(probs))

    pred = torch.argmax(probs).item()

    # ==============================================
    # SAFE LABEL CHECK
    # ==============================================

    total_classes = len(encoder.classes_)

    print("\n================================================")

    print("Prompt:", prompt)

    print("Predicted Label:", pred)

    print("Encoder Classes:", total_classes)

    print("================================================")

    if pred >= total_classes:

        attack_type = "unknown_attack"

    else:

        attack_type = encoder.inverse_transform([pred])[0]

    # ==============================================
    # SAFE NORMALIZATION
    # ==============================================

    if attack_type in ["safe", "safe_prompt", "benign"]:

        attack_type = "benign"

    # ==============================================
    # ATTACK CHECK
    # ==============================================

    is_attack = attack_type != "benign"

    # ==============================================
    # SEVERITY MAP
    # ==============================================

    severity_map = {
        "benign": "SAFE",
        "instruction_override": "MEDIUM RISK",
        "prompt_extraction": "HIGH RISK",
        "persona_hijacking": "MEDIUM RISK",
        "context_manipulation": "HIGH RISK",
        "indirect_injection": "HIGH RISK",
        "obfuscated_attack": "CRITICAL RISK",
        "multi_step_attack": "CRITICAL RISK",
        "unknown_attack": "HIGH RISK",
    }

    severity = severity_map.get(attack_type, "MEDIUM RISK")

    # ==============================================
    # BLOCK ATTACKS
    # ==============================================

    if is_attack:

        attacks += 1

        attack_categories[attack_type] += 1

        return {
            "blocked": True,
            "attack_type": attack_type,
            "severity": severity,
            "response": "BLOCKED FOR SECURITY REASONS",
            "confidence": round(confidence, 4),
            "explanation": explain_attack(attack_type),
        }

    # ==============================================
    # SAFE PROMPT
    # ==============================================

    safe += 1

    cleaned_prompt = sanitize_prompt(prompt)

    reply = ask_llm(cleaned_prompt)

    return {
        "blocked": False,
        "attack_type": "benign",
        "severity": "SAFE",
        "response": reply,
        "confidence": round(confidence, 4),
        "explanation": explain_attack("benign"),
    }
