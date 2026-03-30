from flask import Flask, render_template, request, redirect, url_for, session
import requests
import datetime
import time
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"

VT_API_KEY = "839e507082d42b9c82da344d8d9441d96ef75317779d33e5842d97f6dd09a419"
IPINFO_TOKEN = "3759920718a5c7"

# 📌 CREATE DATABASE
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        value TEXT,
        time TEXT
    )''')

    conn.commit()
    conn.close()

init_db()

# 🔐 LOGIN REQUIRED
def login_required(func):
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

# 📝 SIGNUP
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        conn = sqlite3.connect("users.db")
        c = conn.cursor()

        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
        except:
            return "User already exists"

        conn.close()
        return redirect(url_for('login'))

    return render_template('signup.html')

# 🔑 LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect("users.db")
        c = conn.cursor()

        c.execute("SELECT password FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):
            session['user'] = username
            return redirect(url_for('home'))

    return render_template('login.html')

# 🚪 LOGOUT
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# 🏠 HOME
@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    result = None
    geo = None
    chart_data = None
    user = session.get("user")

    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    if request.method == 'POST':
        ip = request.form.get('ip')
        url_input = request.form.get('url')

        try:
            headers = {"x-apikey": VT_API_KEY}

            # 🔍 IP ANALYSIS
            if ip:
                vt = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers).json()
                stats = vt["data"]["attributes"]["last_analysis_stats"]

                malicious = stats["malicious"]
                suspicious = stats["suspicious"]
                harmless = stats["harmless"]

                threat = "Safe"
                if malicious > 0:
                    threat = "Malicious"
                elif suspicious > 0:
                    threat = "Suspicious"

                result = {"type":"IP","value":ip,"malicious":malicious,"suspicious":suspicious,"harmless":harmless,"threat":threat}
                chart_data = [malicious, suspicious, harmless]

                geo = requests.get(f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}").json()
                if "loc" in geo:
                    lat, lon = geo["loc"].split(",")
                    geo["lat"] = lat
                    geo["lon"] = lon

            # 🔗 URL ANALYSIS
            if url_input:
                submit = requests.post("https://www.virustotal.com/api/v3/urls",
                                       headers=headers, data={"url": url_input}).json()

                analysis_id = submit["data"]["id"]

                for _ in range(10):
                    res = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                                       headers=headers).json()

                    if res["data"]["attributes"]["status"] == "completed":
                        stats = res["data"]["attributes"]["stats"]

                        malicious = stats["malicious"]
                        suspicious = stats["suspicious"]
                        harmless = stats["harmless"]

                        threat = "Safe"
                        if malicious > 0:
                            threat = "Malicious"
                        elif suspicious > 0:
                            threat = "Suspicious"

                        result = {"type":"URL","value":url_input,"malicious":malicious,"suspicious":suspicious,"harmless":harmless,"threat":threat}
                        chart_data = [malicious, suspicious, harmless]
                        break

                    time.sleep(2)

            # 📝 SAVE HISTORY
            c.execute("INSERT INTO history (username, value, time) VALUES (?, ?, ?)",
                      (user, ip or url_input, datetime.datetime.now().strftime("%H:%M:%S")))
            conn.commit()

        except Exception as e:
            result = {"error": str(e)}

    # LOAD USER HISTORY
    c.execute("SELECT value, time FROM history WHERE username=?", (user,))
    history = [{"value": row[0], "time": row[1]} for row in c.fetchall()]

    conn.close()

    return render_template("index.html", result=result, geo=geo, history=history, chart_data=chart_data, user=user)

if __name__ == "__main__":
    app.run(debug=True)




