from .base_analyzer import BaseSentimentAnalyzer
from textblob import TextBlob
import time

class TextBlobAnalyzer(BaseSentimentAnalyzer):
    def analyze(self, text):
        start_time = time.time()
        blob = TextBlob(text)
        polarity = blob.sentiment[0]
        subjectivity = blob.sentiment[1]
        
        if polarity > 0:
            sentiment = "Positive"
        elif polarity < 0:
            sentiment = "Negative"
        else:
            sentiment = "Neutral"
        end_time = time.time()
        return {
            "analyzer": self.get_analyzer_name(),
            "sentiment": sentiment,
            "polarity": polarity,
            "subjectivity": subjectivity,
            "time": end_time - start_time
        }