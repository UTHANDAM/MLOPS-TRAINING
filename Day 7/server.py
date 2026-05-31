from flask import Flask, request, jsonify, send_from_directory
import util, os

app = Flask(__name__, static_folder='client')

@app.route('/')
def index():
    return send_from_directory('client', 'app.html')

@app.route('/model_info', methods=['GET'])
def model_info():
    res = jsonify(util.get_model_info())
    res.headers.add('Access-Control-Allow-Origin', '*')
    return res

@app.route('/predict', methods=['POST'])
def predict():
    data   = request.get_json()
    result = util.predict_claim(data)
    res    = jsonify(result)
    res.headers.add('Access-Control-Allow-Origin', '*')
    return res

if __name__ == '__main__':
    print("=" * 55)
    print("  RiskProof AI — Insurance Fraud Detection Server")
    print("=" * 55)
    util.load_artifacts()
    print("  Server running at: http://127.0.0.1:5000")
    print("=" * 55)
    app.run(debug=True)
