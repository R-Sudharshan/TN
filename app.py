import requests
import base64
from flask import Flask, render_template, request

app = Flask(__name__)

class AdShieldModel:
    def __init__(self):
        self.api_key_virustotal = "5eae5564b4d8e96f22e6425b03b5a0762f914d44ab488d1e4552dbb4bc4f1015"  # VirusTotal API Key

    def analyze(self, url):
                                                                                                        
        vt_result = self.check_url_with_virustotal(url)
        return vt_result

    def check_url_with_virustotal(self, url):
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"

        headers = {
            "x-apikey": self.api_key_virustotal
        }

        response = requests.get(vt_url, headers=headers)

        if response.status_code == 200:
            json_response = response.json()
            analysis_stats = json_response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = analysis_stats.get("malicious", 0)

            if malicious_count > 0:
                return "Suspicious Domain (VirusTotal)"
            else:
                return "Safe Domain (VirusTotal)"
        else:
            return "Unable to check URL with VirusTotal"

model = AdShieldModel()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detect', methods=['POST'])
def detect():
    ad_url = request.form.get('ad_url', '')
    

    vt_result = model.analyze(ad_url)
    

    return render_template('result.html', vt_result=vt_result)

if __name__ == '__main__':
    app.run(debug=True)
