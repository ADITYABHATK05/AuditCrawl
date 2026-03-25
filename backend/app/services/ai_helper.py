from __future__ import annotations

from app.core.config import settings


def generate_summary_with_gemini(findings: list[dict]) -> str:
    if not settings.gemini_api_key:
        return "Gemini summary unavailable (GEMINI_API_KEY not configured)."

    try:
        import google.generativeai as genai

        genai.configure(api_key=settings.gemini_api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        prompt = (
            "Summarize these web security findings in plain language for developers. "
            "Focus on risk and remediation priorities. Findings: "
            f"{findings}"
        )
        response = model.generate_content(prompt)
        return response.text or "Gemini returned an empty summary."
    except Exception as exc:
        return f"Gemini summary failed: {exc}"
