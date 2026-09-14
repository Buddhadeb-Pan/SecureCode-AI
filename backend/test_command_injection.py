from command_injection_analyzer import analyze_python_command_injection
from pprint import pprint

code = '''
import os

def run_command():
    username = input("Enter username: ")
    copied_name = username
    command = "echo " + copied_name
    os.system(command)

run_command()
'''

result = analyze_python_command_injection(code)

pprint(result)