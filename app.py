from fastapi.middleware.cors import CORSMiddleware
import joblib
import shap
import numpy as np
import re
import torch
import time
from statistics import mean
from collections import deque

from fastapi import FastAPI, Request
from pydantic import BaseModel
from transformers import AutoModelForSequenceClassification, AutoTokenizer
from urllib.parse import urlparse
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

# Initialize FastAPI app
app = FastAPI()

# Set up templates
templates = Jinja2Templates(directory="templates")

# Add timing tracking
url_times = deque(maxlen=100)  # Keep last 100 measurements
text_times = deque(maxlen=100)
total_times = deque(maxlen=100)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load models
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
smishing_model_path = "./model/distilbert_model"
smishing_model = AutoModelForSequenceClassification.from_pretrained(smishing_model_path).to(device)
smishing_tokenizer = AutoTokenizer.from_pretrained(smishing_model_path)
phishing_model = joblib.load("./model/adaboost_url_model.pkl")

# SHAP Explainer Setup
masker = shap.maskers.Text(smishing_tokenizer)
explainer = shap.Explainer(lambda x: np.array([predict_message(t) for t in x]), masker)

class MessageInput(BaseModel):
    message: str

def extract_features(url):
    """Extracts all relevant features from a URL."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    
    return {
        "url_length": len(url),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": len(re.findall(r"[!@#$%^&*(),.?\":{}|<>]", url)),
        "domain_length": len(domain),
        "num_subdomains": domain.count("."),
        "has_https": int(url.startswith("https")),
        "has_ip_address": int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', domain))),
        "num_hyphens": domain.count("-"),
        "num_slashes": url.count("/"),
        "num_query_params": url.count("="),
        "has_suspicious_words": int(any(word in url for word in ["login", "bank", "verify", "secure", "update", "account"]))
    }

def extract_urls(text):
    return re.findall(r"https?://\S+|www\.\S+", text)

def predict_url(url):
    url_features = extract_features(url)
    url_vector = np.array(list(url_features.values())).reshape(1, -1)
    phishing_prob = phishing_model.predict_proba(url_vector)[0][1]
    return phishing_prob

def predict_message(text):
    inputs = smishing_tokenizer(text, return_tensors="pt", padding=True, truncation=True).to(device)
    with torch.no_grad():
        outputs = smishing_model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1).cpu().numpy()
    return probs[0][1]  # Probability of smishing

def get_suspicious_words(shap_values, text, threshold=0.1):
    """Return suspicious words based on SHAP values and threshold."""
    words = text.split()
    shap_vals = shap_values.values[0]

    # Get words with high positive SHAP values (suspicious)
    suspicious = [(word, val) for word, val in zip(words, shap_vals) if val > threshold]
    
    # Only use words that are actually above threshold
    suspicious_words = [w for w, _ in suspicious]
    return list(dict.fromkeys(suspicious_words))

def highlight_shap_text(shap_values, text, threshold=0.01):
    """Highlights words in red (dangerous), green (safe) and blue (neutral)."""
    words = text.split()
    shap_vals = shap_values.values[0]
    min_length = min(len(words), len(shap_vals))
    colored_text = []
    highlighted_words = []

    for i in range(min_length):
        word = words[i]
        val = shap_vals[i]

        # Determine color based on SHAP value threshold
        if val > threshold:
            color = "red"  # Dangerous words
            highlighted_words.append(word)
        elif val < -threshold:
            color = "green"  # Safe words
        else:
            color = "blue"  # Neutral words

        colored_text.append(f'<span style="color:{color}; font-weight:bold;">{word}</span>')

    # Append remaining words with neutral styling
    if len(words) > min_length:
        for word in words[min_length:]:
            colored_text.append(f'<span style="color:#0066cc;">{word}</span>')

    return " ".join(colored_text), highlighted_words

@app.get("/")
def get_root():
    return {"message": "Please use POST request with a message to analyze"}

@app.post("/")
def classify_message(input_data: MessageInput):
    total_start_time = time.time()
    
    message = input_data.message
    urls = extract_urls(message)
    text_only = re.sub(r"https?://\S+|www\.\S+", "", message).strip()
    summary = ""
    message_analysis = ""
    url_analysis = []
    highlighted_text = ""
    
    # Measure URL analysis time
    url_start_time = time.time()
    url_probs = [float(predict_url(url)) for url in urls] if urls else []
    max_url_prob = max(url_probs) if url_probs else 0
    url_time = time.time() - url_start_time
    url_times.append(url_time)
    
    # Measure text analysis time
    text_start_time = time.time()
    message_prob = float(predict_message(text_only)) if text_only else 0
    text_time = time.time() - text_start_time
    text_times.append(text_time)
    
    # Determine final probability based on what's present
    if urls and not text_only:  # URL only
        final_prob = max_url_prob
        label = "🚨 Phishing" if final_prob > 0.5 else "Safe"
    elif text_only and not urls:  # Text only
        final_prob = message_prob
        label = "🚨 SMISHING" if final_prob > 0.5 else "Safe"
    else:  # Both URL and text present
        final_prob = float((0.6 * max_url_prob) + (0.4 * message_prob))
        label = "🚨 Phishing" if final_prob > 0.5 else "Safe"

    if urls:
        url_analysis = [("🚨 PHISHING" if prob > 0.5 else "✅ SAFE") for url, prob in zip(urls, url_probs)]
    if text_only:
        message_analysis = ("🚨 SMISHING" if message_prob > 0.5 else "✅ SAFE")
    
    # SHAP Explanation
    shap_values = explainer([text_only]) if text_only else None
    if shap_values:
        highlighted_text, highlighted_words = highlight_shap_text(shap_values, text_only)
        if highlighted_words:
            summary = f"The words {', '.join(highlighted_words)} show strong signs of being dangerous."
        else:
            summary = "None of the words show strong signs of being dangerous."
    
    # Calculate total time
    total_time = time.time() - total_start_time
    total_times.append(total_time)
    
    # Calculate average times
    avg_url_time = round(mean(url_times) * 1000, 2) if url_times else 0  # Convert to milliseconds
    avg_text_time = round(mean(text_times) * 1000, 2) if text_times else 0
    avg_total_time = round(mean(total_times) * 1000, 2) if total_times else 0
    
    return {
        "message_analysis": message_analysis,
        "url_analysis": url_analysis,
        "final_result": label,
        "final_probability": round(final_prob, 4),
        "message_result": "Smishing" if message_prob > 0.5 else "Safe",
        "message_probability": round(message_prob, 4) if text_only else None,
        "url_probability": url_probs if urls else [],
        "url_results": [(url, "Phishing" if prob > 0.5 else "Safe", round(prob, 4)) for url, prob in zip(urls, url_probs)],
        "explanation": highlighted_text,
        "summary": summary,
        "performance_metrics": {
            "avg_url_analysis_time_ms": avg_url_time,
            "avg_text_analysis_time_ms": avg_text_time,
            "avg_total_time_ms": avg_total_time,
            "current_url_time_ms": round(url_time * 1000, 2) if urls else 0,
            "current_text_time_ms": round(text_time * 1000, 2) if text_only else 0,
            "current_total_time_ms": round(total_time * 1000, 2)
        }
    }
