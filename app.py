from flask import Flask, request, jsonify
from flask_cors import CORS
from sentiment_analyzers.tinybert_analyzer import TinyBERTAnalyzer
from sentiment_analyzers.gpt_zero_shot_analyzer import GPTZeroShotAnalyzer
from sentiment_analyzers.mnli_analyzer import MNLIAnalyzer
from sentiment_analyzers.mpnet_analyzer import MPNetAnalyzer
from sentiment_analyzers.vader_analyzer import VaderAnalyzer
from sentiment_analyzers.textblob_analyzer import TextBlobAnalyzer
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
CORS(app)

analyzers = [GPTZeroShotAnalyzer(), VaderAnalyzer(), TextBlobAnalyzer(), MPNetAnalyzer(), MNLIAnalyzer(), TinyBERTAnalyzer()]

# Create a ThreadPoolExecutor
executor = ThreadPoolExecutor(max_workers=len(analyzers))

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    text = data.get('text', '')
    
    futures = [executor.submit(analyzer.analyze, text) for analyzer in analyzers]
    results = [future.result() for future in futures]
    
    #find the analyzer with the max time
    max_time = 0
    max_time_analyzer = None
    for result in results:
        if result['time'] > max_time:
            max_time = result['time']
            max_time_analyzer = result['analyzer']

    return jsonify({
        "text": text,
        "results": results
    })

#health check route
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)