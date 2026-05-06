from __future__ import annotations

from app.core.config import settings


def generate_summary_with_gemini(findings: list[dict]) -> str:
    if not settings.gemini_api_key:
        return "Gemini summary unavailable (GEMINI_API_KEY not configured)."

    try:
        import google.generativeai as genai

        genai.configure(api_key=settings.gemini_api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")
        prompt = (
            "Summarize these web security findings in plain language for developers. "
            "Focus on risk and remediation priorities. Findings: "
            f"{findings}"
        )
        response = model.generate_content(prompt)
        return response.text or "Gemini returned an empty summary."
    except Exception as exc:
        return f"Gemini summary failed: {exc}"

def chat_with_copilot(message: str, history: list[dict], context: dict) -> str:
    if not settings.gemini_api_key:
        return "Gemini API key is not configured. Copilot is offline. Add GEMINI_API_KEY to your .env file."
        
    try:
        import google.generativeai as genai
        genai.configure(api_key=settings.gemini_api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")
        
        system_prompt = (
            "You are AuditCrawl Copilot, an expert web security engineer. "
            "You are assisting a developer with the following vulnerability finding:\n"
            f"Type: {context.get('type', 'Unknown')}\n"
            f"Severity: {context.get('severity', 'Unknown')}\n"
            f"Description: {context.get('description', '')}\n"
            f"Evidence Snippet: {context.get('evidence', '')}\n"
            f"PoC: {context.get('poc', '')}\n\n"
            "Provide concise, actionable advice. If asked for code, write secure, production-ready snippets."
            "Do not output markdown headings like # unless necessary. Be friendly and expert."
        )
        
        # Convert history
        formatted_history = [
            {"role": "user", "parts": [system_prompt]},
            {"role": "model", "parts": ["I am ready to assist you with this vulnerability."]}
        ]
        
        for msg in history:
            role = "user" if msg["role"] == "user" else "model"
            formatted_history.append({"role": role, "parts": [msg["content"]]})
            
        chat = model.start_chat(history=formatted_history)
        response = chat.send_message(message)
        return response.text
    except Exception as exc:
        return f"Copilot error: {str(exc)}"
