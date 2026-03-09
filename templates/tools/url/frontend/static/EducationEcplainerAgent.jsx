import React, { useEffect, useMemo, useState } from "react";

const SYSTEM_PROMPT = `You are a cybersecurity educator embedded in a URL security scanner. 
When given threat data about a scanned URL or QR code, explain it clearly in exactly 3 labeled sections:

**What's Wrong:** [1-2 sentences explaining the specific threat found]
**What Would've Happened:** [1-2 sentences on the real-world consequence if the user had proceeded]  
**What You Should Do:** [1-2 actionable steps the user should take right now]
**💡 Tip:** [1 sentence teaching the user how to spot this type of threat themselves in the future]

Rules:
- Beginner level: Use everyday analogies, no jargon, warm reassuring tone
- Intermediate level: Some technical terms, brief definitions, confident tone
- Advanced level: Full technical detail — mention specific attack vectors, protocols, indicators
- Always be specific to the actual URL and threat data provided
- Never be alarmist, always be empowering
- Keep total response under 120 words`;

const DEMO_SCAN_DATA = {
  url: "paypa1.com/secure-login",
  threatType: "Phishing — Brand Impersonation",
  riskScore: 94,
  flaggedReasons: [
    "Domain uses '1' instead of 'l' (homograph attack)",
    "Domain registered 3 days ago",
    "SSL certificate is self-signed",
    "Redirects to credential harvesting form",
  ],
};

const USER_LEVELS = ["Beginner", "Intermediate", "Advanced"];

function RiskArcGauge({ score }) {
  const clamped = Math.max(0, Math.min(100, score || 0));
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    let frame;
    let start;
    const duration = 750;

    const tick = (ts) => {
      if (!start) start = ts;
      const progress = Math.min((ts - start) / duration, 1);
      setAnimatedScore(Math.round(clamped * progress));
      if (progress < 1) frame = requestAnimationFrame(tick);
    };

    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [clamped]);

  const color =
    animatedScore < 35 ? "#22c55e" : animatedScore < 70 ? "#facc15" : "#ef4444";

  const radius = 64;
  const circumference = Math.PI * radius;
  const dashOffset = circumference - (animatedScore / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center gap-2">
      <svg width="180" height="110" viewBox="0 0 180 110" className="drop-shadow-[0_0_16px_rgba(99,102,241,0.35)]">
        <path d="M 20 90 A 64 64 0 0 1 160 90" fill="none" stroke="#2b2f3b" strokeWidth="14" strokeLinecap="round" />
        <path
          d="M 20 90 A 64 64 0 0 1 160 90"
          fill="none"
          stroke={color}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          style={{ transition: "stroke-dashoffset 240ms linear, stroke 240ms linear" }}
        />
      </svg>
      <div className="-mt-12 text-center">
        <p className="text-3xl font-bold text-slate-100">{animatedScore}</p>
        <p className="text-[11px] uppercase tracking-[0.2em] text-slate-400">Risk Score</p>
      </div>
    </div>
  );
}

export default function EducationalExplainerAgent({ scanResult }) {
  const [userLevel, setUserLevel] = useState("Beginner");
  const [demoMode, setDemoMode] = useState(true);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [explanation, setExplanation] = useState("");
  const [error, setError] = useState("");

  const activeScan = useMemo(() => {
    if (demoMode || !scanResult) return DEMO_SCAN_DATA;
    return {
      url: scanResult.url,
      threatType: scanResult.threatType,
      riskScore: scanResult.riskScore,
      flaggedReasons: scanResult.flaggedReasons || [],
    };
  }, [demoMode, scanResult]);

  const analyzeThreat = async () => {
    setIsAnalyzing(true);
    setError("");
    setExplanation("");

    try {
      const response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "anthropic-version": "2023-06-01",
          "anthropic-dangerous-direct-browser-access": "true",
        },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 260,
          system: SYSTEM_PROMPT,
          stream: true,
          messages: [
            {
              role: "user",
              content: `User level: ${userLevel}\n\nScan data:\nURL: ${activeScan.url}\nThreat Type: ${activeScan.threatType}\nRisk Score: ${activeScan.riskScore}\nFlagged Reasons:\n- ${activeScan.flaggedReasons.join("\n- ")}`,
            },
          ],
        }),
      });

      if (!response.ok || !response.body) {
        const details = await response.text();
        throw new Error(details || `API call failed (${response.status})`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder("utf-8");
      let buffer = "";

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const events = buffer.split("\n\n");
        buffer = events.pop() || "";

        for (const event of events) {
          const line = event
            .split("\n")
            .find((entry) => entry.startsWith("data:"));

          if (!line) continue;
          const payload = line.replace(/^data:\s*/, "");
          if (payload === "[DONE]") continue;

          let parsed;
          try {
            parsed = JSON.parse(payload);
          } catch {
            continue;
          }

          if (parsed.type === "content_block_delta" && parsed.delta?.type === "text_delta") {
            setExplanation((prev) => prev + parsed.delta.text);
          }
        }
      }
    } catch (err) {
      setError(err.message || "Could not generate explanation. Please retry.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <section className="w-full rounded-2xl border border-cyan-500/40 bg-[#090c14] p-5 shadow-[0_0_45px_rgba(34,211,238,0.1)]">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 border-b border-cyan-900/70 pb-4">
        <h2 className="text-lg font-semibold uppercase tracking-[0.2em] text-cyan-300">Educational Explainer Agent</h2>

        <div className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 p-1">
          {USER_LEVELS.map((level) => (
            <button
              key={level}
              onClick={() => setUserLevel(level)}
              className={`rounded-md px-3 py-1 text-xs font-medium transition ${
                userLevel === level ? "bg-cyan-400 text-slate-950" : "text-slate-300 hover:bg-slate-800"
              }`}
            >
              {level}
            </button>
          ))}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-[1.3fr,1fr]">
        <div className="rounded-xl border border-slate-700 bg-[#0c101a] p-4">
          <div className="mb-3 flex items-center justify-between text-xs text-slate-400">
            <span>Scan Input</span>
            <label className="inline-flex cursor-pointer items-center gap-2">
              <input
                type="checkbox"
                checked={demoMode}
                onChange={(e) => setDemoMode(e.target.checked)}
                className="h-4 w-4 accent-cyan-400"
              />
              Demo Mode
            </label>
          </div>

          <p className="mb-2 font-mono text-sm text-cyan-300">{activeScan.url || "No URL supplied yet"}</p>
          <p className="mb-2 text-sm text-slate-300">Threat: <span className="text-rose-300">{activeScan.threatType}</span></p>
          <ul className="space-y-1 text-xs text-slate-400">
            {activeScan.flaggedReasons.map((reason) => (
              <li key={reason}>• {reason}</li>
            ))}
          </ul>

          <button
            onClick={analyzeThreat}
            disabled={isAnalyzing}
            className="mt-4 w-full rounded-lg bg-gradient-to-r from-cyan-400 to-indigo-400 px-4 py-2 text-sm font-semibold text-slate-950 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isAnalyzing ? "AI is analyzing..." : "Generate Educational Explanation"}
          </button>
        </div>

        <div className="rounded-xl border border-slate-700 bg-[#0c101a] p-4">
          <RiskArcGauge score={activeScan.riskScore} />
        </div>
      </div>

      <div className="mt-4 rounded-xl border border-indigo-800/70 bg-[#0a0e18] p-4">
        {isAnalyzing && (
          <div className="space-y-2">
            <p className="text-xs uppercase tracking-[0.18em] text-cyan-400">AI is analyzing...</p>
            <div className="h-3 animate-pulse rounded bg-slate-700/80" />
            <div className="h-3 w-11/12 animate-pulse rounded bg-slate-700/80" />
            <div className="h-3 w-9/12 animate-pulse rounded bg-slate-700/80" />
          </div>
        )}

        {!isAnalyzing && error && (
          <div className="rounded-lg border border-rose-700 bg-rose-900/20 p-3 text-sm text-rose-300">
            {error}
          </div>
        )}

        {!isAnalyzing && !error && !explanation && (
          <p className="text-sm text-slate-400">Run the agent to receive a 3-part educational explanation + security tip.</p>
        )}

        {explanation && (
          <pre className="whitespace-pre-wrap font-sans text-sm leading-6 text-slate-200">{explanation}</pre>
        )}
      </div>
    </section>
  );
}