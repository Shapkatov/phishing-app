from flask import Flask, request, render_template
import re
import os

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

    if score >= 5:
        return "🔴 High Risk (Phishing likely)"
    elif score >= 3:
        return "🟠 Medium Risk"
    else:
        return "🟢 Low Risk (Safe)"


@app.route("/", methods=["GET", "POST"])
def home():
    result = ""

    if request.method == "POST":
        url = request.form["url"]
        result = analyze_url(url)

        history.insert(0, f"{url} → {result}")

        if len(history) > 5:
            history.pop()

    return render_template("index.html", result=result, history=history)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)