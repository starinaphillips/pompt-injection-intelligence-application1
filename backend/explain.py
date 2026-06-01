def explain_attack(prompt, attack_type):

    explanations = {
        "instruction_override":
        "Prompt attempts to override system instructions.",

        "prompt_extraction":
        "Prompt tries to reveal hidden system prompts.",

        "persona_hijacking":
        "Prompt attempts to change the AI's role or identity.",

        "context_manipulation":
        "Prompt modifies system context to change behaviour.",

        "indirect_injection":
        "Prompt attempts to insert malicious instructions via external content.",

        "benign":
        "Prompt appears safe and does not contain malicious instructions."
    }

    return explanations.get(attack_type, "Unknown attack type")