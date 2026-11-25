"""LLM assistant: read-only analysis over real DB context. It cannot execute actions; falls back to deterministic output."""
import json, os, httpx
from sqlalchemy import select, func
from .models import *
SYSTEM = ("You are a SOC analysis assistant. Use ONLY the JSON context provided; never invent events, IPs, users, or evidence. "
          "If something is unknown say so. You cannot take actions, only recommend. Reply with ONE JSON object with keys: "
          "summary (string), impact (string), evidence (array of strings taken from the context), risk_explanation (string), "
          "actions (array of strings), answer (string answering the user's question, or empty).")
def incident_context(db, inc):
    ts = db.scalars(select(Threat).where(Threat.incident_id == inc.id)).all()
    ras = db.scalars(select(RiskAssessment).where(RiskAssessment.incident_id == inc.id).order_by(RiskAssessment.id.desc())).first()
    ev = db.scalars(select(Event).join(IncidentEvent, IncidentEvent.event_id == Event.id).where(IncidentEvent.incident_id == inc.id).order_by(Event.timestamp).limit(40)).all()
    return {"incident": {"title": inc.title, "status": inc.status, "risk_score": inc.risk_score, "risk_level": inc.risk_level},
            "threats": [{"category": t.category, "description": t.description, "severity": t.severity, "confidence": t.confidence} for t in ts],
            "risk_factors": ras.factors if ras else [], "risk_explanation": ras.explanation if ras else "",
            "events": [{"time": e.timestamp.isoformat(), "type": e.event_type, "user": e.user_identity, "ip": e.ip, "resource": e.resource, "action": e.action, "status": e.status} for e in ev]}
def global_context(db):
    cnt = lambda m, *w: db.scalar(select(func.count()).select_from(m).where(*w)) or 0
    inc = db.scalars(select(Incident).where(Incident.status.in_(["new", "investigating", "in_progress"])).order_by(Incident.risk_score.desc()).limit(5)).all()
    ev = db.scalars(select(Event).order_by(Event.timestamp.desc()).limit(30)).all()
    return {"totals": {"events": cnt(Event), "threats": cnt(Threat), "open_incidents": len(inc)},
            "top_open_incidents": [{"title": i.title, "risk_score": i.risk_score, "risk_level": i.risk_level} for i in inc],
            "recent_events": [{"time": e.timestamp.isoformat(), "type": e.event_type, "user": e.user_identity, "ip": e.ip, "resource": e.resource, "status": e.status} for e in ev]}
def fallback(ctx, q):
    inc = ctx.get("incident"); th = ctx.get("threats", [])
    if not inc:
        t = ctx["totals"]; return {"summary": f"{t['events']} events, {t['threats']} threats, {t['open_incidents']} open incidents.", "impact": "See top open incidents.",
            "evidence": [f"{i['title']} ({i['risk_level']} {i['risk_score']})" for i in ctx["top_open_incidents"]], "risk_explanation": "Scores come from the rule-based risk engine.",
            "actions": ["Review the highest-risk open incident first."], "answer": ""}
    cats = sorted({t["category"] for t in th})
    return {"summary": f"Incident '{inc['title']}' is {inc['risk_level']} ({inc['risk_score']}/100) with {len(th)} correlated threat(s): {', '.join(cats)}.",
            "impact": "Possible account compromise or unauthorized access; confirm by reviewing the evidence." if len(cats) > 1 else "Limited to a single indicator; impact unconfirmed.",
            "evidence": [t["description"] for t in th][:8], "risk_explanation": ctx["risk_explanation"] or "No risk assessment recorded.",
            "actions": ["Verify the activity with the account owner.", "Reset credentials / revoke sessions if not legitimate.", "Block or review the source IP.", "Review access to sensitive resources in the timeline.", "Document findings in the incident notes."],
            "answer": ctx["risk_explanation"] if q else ""}
def analyze(ctx, question=None):
    key = os.getenv("ANTHROPIC_API_KEY")
    if key:
        try:
            r = httpx.post("https://api.anthropic.com/v1/messages", timeout=30, headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
                json={"model": os.getenv("LLM_MODEL", "claude-sonnet-5-5"), "max_tokens": 1000, "system": SYSTEM,
                      "messages": [{"role": "user", "content": f"Context:\n{json.dumps(ctx, default=str)}\n\nQuestion: {question or 'Summarize and recommend actions.'}"}]})
            r.raise_for_status(); txt = r.json()["content"][0]["text"].strip().strip("`").removeprefix("json").strip()
            out = json.loads(txt)
            if all(k in out for k in ("summary", "impact", "evidence", "risk_explanation", "actions")): return {**out, "answer": out.get("answer", ""), "source": "llm"}
        except Exception: pass
    return {**fallback(ctx, question), "source": "fallback"}
