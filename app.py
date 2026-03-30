from flask import Flask, render_template, request
import requests
import datetime
import time

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
            headers = {"x-apikey": VT_API_KEY}

            # 🔍 IP ANALYSIS
            if ip:
                vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                response = requests.get(vt_url, headers=headers)
                data = response.json()

                stats = data["data"]["attributes"]["last_analysis_stats"]

                malicious = stats["malicious"]
                suspicious = stats["suspicious"]
                harmless = stats["harmless"]

                threat = "Safe"
                if malicious > 0:
                    threat = "Malicious"
                elif suspicious > 0:
                    threat = "Suspicious"

                result = {
                    "type": "IP",
                    "value": ip,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "threat": threat
                }

                chart_data = [malicious, suspicious, harmless]

                # 🌍 GEOLOCATION
                geo_res = requests.get(f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}")
                geo = geo_res.json()

                # Extract lat/lon
                if "loc" in geo:
                    lat, lon = geo["loc"].split(",")
                    geo["lat"] = lat
                    geo["lon"] = lon

            # 🔗 URL ANALYSIS
            if url_input:
                submit_url = "https://www.virustotal.com/api/v3/urls"
                submit_res = requests.post(submit_url, headers=headers, data={"url": url_input})
                submit_data = submit_res.json()

                analysis_id = submit_data["data"]["id"]
                result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

                for _ in range(10):
                    result_res = requests.get(result_url, headers=headers)
                    result_data = result_res.json()

                    status = result_data["data"]["attributes"]["status"]

                    if status == "completed":
                        stats = result_data["data"]["attributes"]["stats"]

                        malicious = stats["malicious"]
                        suspicious = stats["suspicious"]
                        harmless = stats["harmless"]

                        threat = "Safe"
                        if malicious > 0:
                            threat = "Malicious"
                        elif suspicious > 0:
                            threat = "Suspicious"

                        result = {
                            "type": "URL",
                            "value": url_input,
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "harmless": harmless,
                            "threat": threat
                        }

                        chart_data = [malicious, suspicious, harmless]
                        break

                    time.sleep(2)

                else:
                    result = {
                        "type": "URL",
                        "value": url_input,
                        "message": "Still processing... try again"
                    }

            # 📝 HISTORY
            history.append({
                "value": ip or url_input,
                "time": datetime.datetime.now().strftime("%H:%M:%S")
            })

        except Exception as e:
            result = {"error": str(e)}

    return render_template("index.html", result=result, geo=geo, history=history, chart_data=chart_data)


if __name__ == "__main__":
    app.run(debug=True)





