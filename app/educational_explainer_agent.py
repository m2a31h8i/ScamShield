from app.services.ai_service import generate_ai_response


def build_prompt(threat_type, target, risk_score, indicators, user_level):

    return f"""
You are a cybersecurity educator.

Explain threats in simple language.

Threat Information:
Threat Type: {threat_type}
Target: {target}
Risk Score: {risk_score}/100
Indicators: {', '.join(indicators)}

User Level: {user_level}

Respond ONLY in this format:

TITLE:
WHAT_IS_WRONG:
WHAT_WOULD_HAPPEN:
WHAT_TO_DO:
TIP:

Keep the explanation under 80 words.
"""


def parse_ai_output(text):

    sections = {
        "title": "",
        "whats_wrong": "",
        "what_would_happen": "",
        "what_to_do": "",
        "tip": ""
    }

    lines = text.split("\n")

    for line in lines:
        if line.startswith("TITLE:"):
            sections["title"] = line.replace("TITLE:", "").strip()

        elif line.startswith("WHAT_IS_WRONG:"):
            sections["whats_wrong"] = line.replace("WHAT_IS_WRONG:", "").strip()

        elif line.startswith("WHAT_WOULD_HAPPEN:"):
            sections["what_would_happen"] = line.replace("WHAT_WOULD_HAPPEN:", "").strip()

        elif line.startswith("WHAT_TO_DO:"):
            sections["what_to_do"] = line.replace("WHAT_TO_DO:", "").strip()

        elif line.startswith("TIP:"):
            sections["tip"] = line.replace("TIP:", "").strip()

    return sections


def run_explainer_agent(threat_type, target, risk_score, indicators, user_level):

    prompt = build_prompt(threat_type, target, risk_score, indicators, user_level)

    ai_output = generate_ai_response(prompt)

    parsed = parse_ai_output(ai_output)

    return {
        "title": parsed["title"] or f"{threat_type} Detected",
        "whats_wrong": parsed["whats_wrong"],
        "what_would_happen": parsed["what_would_happen"],
        "what_to_do": parsed["what_to_do"],
        "tip": parsed["tip"],
        "risk_score": risk_score,
        "user_level": user_level
    }