from flask import Flask, render_template, jsonify
import time

app = Flask(__name__)

LOG_FILE = "dns_log.txt"

def read_logs():
    """Reads the latest DNS logs."""
    try:
        with open(LOG_FILE, "r") as file:
            logs = file.readlines()[-20:]  # Show last 20 logs
        return logs
    except FileNotFoundError:
        return ["No logs found."]

@app.route('/')
def index():
    """Render the Web UI."""
    return render_template("index.html")

@app.route('/logs')
def get_logs():
    """Return log data as JSON for frontend updates."""
    logs = read_logs()
    return jsonify(logs)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

