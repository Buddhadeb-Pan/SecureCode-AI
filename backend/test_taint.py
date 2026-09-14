from python_taint_analyzer import analyze_python_sql_injection
from pprint import pprint


code = '''
username = input("Enter username: ")

name = username

query = (
    "SELECT * FROM users WHERE name = '"
    + name
    + "'"
)

cursor.execute(query)
'''


result = analyze_python_sql_injection(code)

pprint(result)