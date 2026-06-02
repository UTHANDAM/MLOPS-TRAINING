from flask import Flask, jsonify, request

import util


app = Flask(__name__)


def cors(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    return response


@app.route("/health", methods=["GET"])
def health():
    return cors(jsonify({"status": "ok", "service": "RiskProof AI Claim Risk API"}))


@app.route("/get_model_metadata", methods=["GET"])
def get_model_metadata():
    return cors(jsonify(util.get_model_metadata()))


@app.route("/get_form_options", methods=["GET"])
def get_form_options():
    return cors(jsonify(util.get_form_options()))


@app.route("/predict_claim_risk", methods=["GET", "POST", "OPTIONS"])
def predict_claim_risk():
    if request.method == "OPTIONS":
        return cors(jsonify({"status": "ok"}))

    payload = request.get_json(silent=True)
    if payload is None:
        payload = request.form.to_dict()

    result = util.predict_claim_risk(payload)
    return cors(jsonify(result))


if __name__ == "__main__":
    print("Starting Flask server for RiskProof AI claim-risk prediction...")
    util.load_saved_artifacts()
    app.run(host="0.0.0.0", port=5000, debug=False)
