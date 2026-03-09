from fastapi import FastAPI, File, UploadFile
import numpy as np
import cv2
from qreader import QReader
from transformers import pipeline

app = FastAPI()

qr_reader = QReader()

classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

SCAM_LABELS = [
    "phishing scam",
    "UPI payment scam",
    "crypto scam",
    "malicious link",
    "safe message"
]

def parse_upi_string(qr_data):

    details = {}

    if "upi://" not in qr_data.lower():
        return details

    parts = qr_data.split("?")

    if len(parts) < 2:
        return details

    params = parts[1].split("&")

    for param in params:

        if "=" in param:
            key,value = param.split("=",1)
            details[key] = value

    return details


@app.get("/health")
def health():
    return {"status": "QR Analyzer Running"}


@app.post("/scan-qr")

async def scan_qr(file: UploadFile = File(...)):

    contents = await file.read()

    nparr = np.frombuffer(contents, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    if img is None:
        return {"error":"Invalid image"}

    decoded_texts = qr_reader.detect_and_decode(image=img)

    if not decoded_texts or not decoded_texts[0]:
        return {"error":"No QR code detected"}

    qr_data = decoded_texts[0]

    risk = 0
    explanation = []

    upi_details = parse_upi_string(qr_data)

    if upi_details:

        explanation.append("UPI payment QR detected")

        payee = upi_details.get("pa")
        amount = upi_details.get("am")

        if payee:
            explanation.append(f"UPI ID: {payee}")

        if amount:
            explanation.append(f"Amount requested ₹{amount}")
            risk += 0.3

    if qr_data.startswith("http"):
        explanation.append("QR contains URL")
        risk += 0.3

    result = classifier(qr_data, SCAM_LABELS)

    ai_score = max(result["scores"])
    ai_label = result["labels"][result["scores"].index(ai_score)]

    risk = min(risk + ai_score * 0.6,1)

    return {
        "decoded_data": qr_data,
        "risk_score": round(risk,2),
        "category": ai_label,
        "explanation": explanation
    }