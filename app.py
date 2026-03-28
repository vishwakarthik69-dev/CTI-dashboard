from flask import Flask, render_template, request
import requests, os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/check', methods=['POST'])
def check():
    ip = request.form.get('ip')
    print("User entered IP:",ip)

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": os.getenv("VT_API_KEY")}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']

        malicious = stats['malicious']
        suspicious = stats['suspicious']
        harmless = stats['harmless']

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
    else:
        return "Error fetching data"

if __name__ == "__main__":
    app.run(host='0.0.0.0',port=10000)




