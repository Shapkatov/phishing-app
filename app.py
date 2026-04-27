from flask import Flask, request, render_template_string
import re

app = Flask(__name__)

history = []

def analyze_url(url):
    score = 0

    suspicious_keywords = ["login", "verify", "secure", "account", "update"]

    if any(word in url.lower() for word in suspicious_keywords):
        score += 2

    if re.match(r"http://\d+\.\d+\.\d+\.\d+", url):
        score += 3

    if len(url) > 75:
        score += 1

    if "@" in url:
        score += 2

    if "-" in url and "secure" in url:
        score += 2

    # уровень риска
    if score >= 5:
        return "🔴 High Risk (Phishing likely)"
    elif score >= 3:
        return "🟠 Medium Risk"
    else:
        return "🟢 Low Risk (Safe)"


HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Phishing Detector</title>
    <style>
        body {
            font-family: Arial;
            background: linear-gradient(to right, #141e30, #243b55);
            color: white;
            text-align: center;
            padding-top: 50px;
        }
        input {
            padding: 12px;
            width: 300px;
            border-radius: 8px;
            border: none;
        }
        button {
            padding: 12px 20px;
            border-radius: 8px;
            border: none;
            background: #00c6ff;
            color: white;
            cursor: pointer;
            font-size: 16px;
        }
        .box {
            background: rgba(255,255,255,0.1);
            padding: 30px;
            border-radius: 15px;
            display: inline-block;
        }
        .history {
            margin-top: 30px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="box">
        <h1>🔐 Phishing Detection Tool</h1>
        <p>Check if a website is safe</p>

        <form method="POST">
            <input type="text" name="url" placeholder="Enter URL" required>
            <br><br>
            <button type="submit">Check</button>
        </form>

        <h2>{{ result }}</h2>

        <div class="history">
            <h3>History</h3>
            {% for item in history %}
                <p>{{ item }}</p>
            {% endfor %}
        </div>

        <p style="font-size: 12px;">This tool uses rule-based detection</p>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def home():
    result = ""

    if request.method == "POST":
        url = request.form["url"]
        result = analyze_url(url)

        history.insert(0, f"{url} → {result}")

        if len(history) > 5:
            history.pop()

    return render_template_string(HTML, result=result, history=history)

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
