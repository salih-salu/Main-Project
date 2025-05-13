




import os
import pickle
import numpy as np
import tensorflow as tf
import requests
import time
from flask import Flask, request, jsonify
from keras.preprocessing.sequence import pad_sequences
from flask_cors import CORS

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Load LSTM Model & Tokenizer
MODEL_PATH = "phishing_url_lstm_model.h5"
TOKENIZER_PATH = "tokenizer.pkl"
API_KEY = "3a1788c28847851d112022a0cf671478bbc87bdac44b507a3425f9d358f6c5a8"

loaded_model = tf.keras.models.load_model(MODEL_PATH)

# Load tokenizer
with open(TOKENIZER_PATH, "rb") as f:
    loaded_tokenizer = pickle.load(f)

MAX_LEN = 100


# VirusTotal URL Scan
def check_virustotal(url):
    headers = {"x-apikey": API_KEY}
    try:
        # Step 1: Submit URL to VirusTotal
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=10)
        
        if response.status_code == 200:
            scan_data = response.json()
            scan_id = scan_data.get("data", {}).get("id")

            if not scan_id:
                print("Error: Invalid Scan ID in VirusTotal response")
                return "Pending"

            report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
            
            try:
                report_response = requests.get(report_url, headers=headers, timeout=10)
                if report_response.status_code == 200:
                    data = report_response.json()
                    attributes = data.get("data", {}).get("attributes", {})

                    if "status" not in attributes:
                        print("Error: 'status' field missing in VirusTotal response")
                        return "Pending"

                    status = attributes["status"]
                    print(f"VirusTotal Scan Status: {status}")

                    if status == "completed":
                        stats = attributes.get("stats", {})
                        malicious_count = stats.get("malicious", 0)
                        suspicious_count = stats.get("suspicious", 0)

                        if malicious_count > 0:
                            return "Phishing"
                        elif suspicious_count > 0:
                            return "Suspicious"
                        else:
                            return "Safe"
                    else:
                        return "Pending"

                elif report_response.status_code == 429:
                    print("Error: VirusTotal API rate limit exceeded")
                    return "Pending to rate limit"

                elif report_response.status_code == 403:
                    print("Error: VirusTotal API key may be invalid or blocked")
                    return "maybe API invalid"

            except requests.exceptions.RequestException as e:
                print(f"Request failed: {e}")
                return "Request Failed"

        else:
            print(f"Error: Unexpected VirusTotal response code {response.status_code}")
            return "Pending"

    except requests.exceptions.RequestException as e:
        print(f"Error contacting VirusTotal API: {e}")
        return "Error contacting VirusTotal API"


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data.get("url")

    # LSTM Model Prediction
    test_sequence = loaded_tokenizer.texts_to_sequences([url])
    test_padded = pad_sequences(test_sequence, maxlen=MAX_LEN, padding="post", truncating="post")
    prediction = loaded_model.predict(test_padded)[0][0]

    lstm_result = "Phishing" if prediction > 0.7 else "Safe" if prediction < 0.3 else "Suspicious"
    vt_result = check_virustotal(url)

    # Determine final result
    if vt_result == "Phishing" or lstm_result == "Phishing":
        final_result = "Phishing"
    elif vt_result == "Suspicious" or lstm_result == "Suspicious":
        final_result = "Suspicious"
    elif vt_result == "Pending":
        final_result = "Pending"
    else:
        final_result = "Safe"

    return jsonify({
        "lstm_prediction": lstm_result,
        "virustotal_prediction": vt_result,
        "final_prediction": final_result
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
