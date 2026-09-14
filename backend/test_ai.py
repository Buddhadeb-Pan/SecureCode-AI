from ai_client import call_ai


print("1. test_ai.py started...", flush=True)

system_prompt = """
You are a cybersecurity assistant.
Answer clearly and briefly.
"""

user_prompt = """
What is SQL Injection?
Explain it in one short sentence.
"""


try:

    print("2. Sending request to OpenRouter...", flush=True)

    response = call_ai(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        temperature=0.2,
        max_tokens=100,
    )

    print("3. Response received!", flush=True)

    print("\n==============================")
    print("OPENROUTER AI TEST SUCCESS")
    print("==============================\n")

    print(response)

except Exception as error:

    print("\n==============================")
    print("OPENROUTER AI TEST FAILED")
    print("==============================\n")

    print(type(error).__name__)
    print(error)