from fastapi import APIRouter
from pydantic import BaseModel
from transformers import pipeline
import re

router = APIRouter()

classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

SCAM_LABELS = [
    "phishing scam",
    "job offer scam",
    "UPI payment scam",
    "crypto scam",
    "refund scam",
    "safe message"
]

class InputData(BaseModel):
    text: str


def urgency_score(text):
    urgent_words = ["urgent","immediately","now","asap","limited time"]
    return sum(word in text.lower() for word in urgent_words)*0.1


def link_score(text):
    suspicious_keywords = ["verify","login","free","reward"]
    urls = re.findall(r'(https?://\S+)', text)

    score=0

    for url in urls:
        score += sum(word in url.lower() for word in suspicious_keywords)*0.2

    return min(score,0.8)


@router.post("/analyze-text")

def analyze_text(data: InputData):

    text=data.text

    result=classifier(text,SCAM_LABELS)

    ai_score=max(result["scores"])
    ai_label=result["labels"][result["scores"].index(ai_score)]

    final_score=min(ai_score+urgency_score(text)+link_score(text),1)

    explanation=[]

    if urgency_score(text)>0:
        explanation.append("Urgency language detected")

    if link_score(text)>0:
        explanation.append("Suspicious link keywords detected")

    if ai_label!="safe message":
        explanation.append(f"AI detected pattern similar to {ai_label}")

    return{
        "risk_score":round(final_score,2),
        "category":ai_label,
        "explanation":explanation
    }