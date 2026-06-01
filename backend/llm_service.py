import requests

def ask_llm(prompt: str):
    try:
        res = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "phi",
                "prompt": prompt,
                "stream": False
            }
        )

        data = res.json()

        print("FULL RESPONSE:", data)   # 🔥 debug

        # ✅ correct extraction
        if "response" in data:
            return data["response"]
        else:
            return f"Unexpected format: {data}"

    except Exception as e:
        return f"Ollama error: {str(e)}"