from flask import Flask, request, jsonify
from flask_cors import CORS
from sentiment_analyzers.tinybert_analyzer import TinyBERTAnalyzer
from sentiment_analyzers.gpt_zero_shot_analyzer import GPTZeroShotAnalyzer
from sentiment_analyzers.mnli_analyzer import MNLIAnalyzer
from sentiment_analyzers.mpnet_analyzer import MPNetAnalyzer
from sentiment_analyzers.vader_analyzer import VaderAnalyzer
from sentiment_analyzers.textblob_analyzer import TextBlobAnalyzer
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Change this to something secure!

jwt = JWTManager(app)

analyzers = [GPTZeroShotAnalyzer(), VaderAnalyzer(), TextBlobAnalyzer(), MPNetAnalyzer(), MNLIAnalyzer(), TinyBERTAnalyzer()]

# Create a ThreadPoolExecutor
executor = ThreadPoolExecutor(max_workers=len(analyzers))
users = {}
  
@app.route('/register', methods=['POST'])
def register_api():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400
    if username in users:
        return jsonify({"msg": "Username already exists"}), 400
    users[username] = generate_password_hash(password)
    return jsonify({"msg": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400
    if username not in users or not check_password_hash(users[username], password):
        return jsonify({"msg": "Bad username or password"}), 401
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    text = data.get('text', '')
    
    futures = [executor.submit(analyzer.analyze, text) for analyzer in analyzers]
    results = [future.result() for future in futures]
    
    #find the analyzer with the max time
    max_time = 0
    for result in results:
        if result['time'] > max_time:
            max_time = result['time']

    return jsonify({
        "text": text,
        "results": results
    })

MOCK_PAST_ANALYSES = [
    {
        "text": "I love this product! It's amazing and works perfectly.",
        "results": [
            {"analyzer": "Sentiment Analysis", "sentiment": "Positive", "score": 0.9},
            {"analyzer": "Entity Recognition", "sentiment": "N/A", "score": 0, "entities": ["product"]}
        ]
    },
    {
        "text": "The customer service was terrible. I'm very disappointed.",
        "results": [
            {"analyzer": "Sentiment Analysis", "sentiment": "Negative", "score": 0.8},
            {"analyzer": "Entity Recognition", "sentiment": "N/A", "score": 0, "entities": ["customer service"]}
        ]
    }
]

@app.route('/past-analyses', methods=['GET'])
@jwt_required()
def get_past_analyses():
    current_user = get_jwt_identity()
    return jsonify(MOCK_PAST_ANALYSES), 200



@app.route('/health', methods=['GET'])
def health_check_api():
    return jsonify({
        'status': 'healthy'
    })
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)