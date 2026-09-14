from xss_analyzer import analyze_python_xss
from pprint import pprint


code = '''
from flask import Flask, request, render_template_string
import html

app = Flask(__name__)


@app.route("/unsafe")
def unsafe():
    username = request.args.get("name")

    copied_name = username

    page = "<h1>Hello " + copied_name + "</h1>"

    return render_template_string(page)


@app.route("/safe")
def safe():
    username = request.args.get("name")

    safe_name = html.escape(username)

    page = "<h1>Hello " + safe_name + "</h1>"

    return render_template_string(page)
'''


result = analyze_python_xss(code)

pprint(result)