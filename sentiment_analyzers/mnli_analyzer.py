from transformers import pipeline

from sentiment_analyzers.base_analyzer import BaseSentimentAnalyzer
import time

class MNLIAnalyzer(BaseSentimentAnalyzer):
    def __init__(self):
        self.pipe = pipeline(model="facebook/bart-large-mnli")
        self.candidate_labels = ["negative physician review", "positive physician review", "neutral physician review"]

    def analyze(self, text):
        start_time = time.time()
        predictions = self.pipe(text, candidate_labels=self.candidate_labels)
        end_time = time.time()

        # Get the label with the highest score
        top_label = predictions['labels'][0]        
        sentiment = top_label.split()[0].capitalize()

        return {
            "analyzer": "MNLIAnalyzer",
            "sentiment": sentiment,
            "scores": {label: score for label, score in zip(predictions['labels'], predictions['scores'])},
            "time": end_time - start_time
        }