from hardcoded_secret_analyzer import (
    analyze_python_hardcoded_secrets
)

from pprint import pprint


code = '''
import os

password = "SuperSecretPassword2026"

ADMIN_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456"

jwt_secret = "very-long-secret-key-for-production"
api_key = "sk-1234567890abcdefghijklmnop"

api_key = os.getenv("API_KEY")
'''


result = analyze_python_hardcoded_secrets(
    code
)

pprint(result)