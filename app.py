from flask import Flask, render_template, request
import requests, os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

@app.route('/')
def home():
    return render_template("index.html", ip=None)

@app.route('/check', methods=['POST'])
def check():
    ip = request.form.get('ip')

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": os.getenv("VT_API_KEY")}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()

        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)

        if malicious > 5:
            threat = "HIGH"
        elif suspicious > 0:
            threat = "MEDIUM"
        else:
            threat = "LOW"

        return render_template(
            "index.html",
            ip=ip,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            threat=threat
        )

    return render_template("index.html", ip=None)

if __name__ == "__main__":
    app.run(debug=True)





