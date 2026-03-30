from flask import Flask, render_template, request
import requests
import datetime

app = Flask(__name__)

history = []

VT_API_KEY = "839e507082d42b9c82da344d8d9441d96ef75317779d33e5842d97f6dd09a419"
IPINFO_TOKEN = "3759920718a5c7"

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    geo = None
    chart_data = None

    if request.method == 'POST':
        ip = request.form.get('ip')
        url_input = request.form.get('url')

        try:
            # 🔍 IP Analysis (VirusTotal)
            if ip:
                vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                headers = {"x-apikey": VT_API_KEY}

                response = requests.get(vt_url, headers=headers)
                data = response.json()

                stats = data["data"]["attributes"]["last_analysis_stats"]

                malicious = stats["malicious"]
                suspicious = stats["suspicious"]
                harmless = stats["harmless"]

                if malicious > 0:
                    threat = "Malicious"
                elif suspicious > 0:
                    threat = "Suspicious"
                else:
                    threat = "Safe"

                result = {
                    "type": "IP",
                    "value": ip,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "threat": threat
                }

                chart_data = [malicious, suspicious, harmless]

                # 🌍 Geolocation
                geo_res = requests.get(f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}")
                geo = geo_res.json()

            # 🔗 URL Analysis (VirusTotal)
            if url_input:
                vt_url = "https://www.virustotal.com/api/v3/urls"
                headers = {"x-apikey": VT_API_KEY}

                scan_res = requests.post(vt_url, headers=headers, data={"url": url_input})
                scan_data = scan_res.json()

                result = {
                    "type": "URL",
                    "value": url_input,
                    "message": "URL submitted for scanning"
                }

            # 📝 History
            history.append({
                "value": ip or url_input,
                "time": datetime.datetime.now().strftime("%H:%M:%S")
            })

        except Exception as e:
            result = {"error": "Something went wrong"}

    return render_template("index.html", result=result, geo=geo, history=history, chart_data=chart_data)


if __name__ == "__main__":
    app.run(debug=True)





