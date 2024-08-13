from .base_analyzer import BaseSentimentAnalyzer
import nltk
from nltk.sentiment import SentimentIntensityAnalyzer
import time
nltk.download('vader_lexicon', quiet=True)

class VaderAnalyzer(BaseSentimentAnalyzer):
    def analyze(self, text):
        start_time = time.time()
        sia = SentimentIntensityAnalyzer()
        scores = sia.polarity_scores(text)
        
        if scores['compound'] >= 0.05:
            sentiment = "Positive"
        elif scores['compound'] <= -0.05:
            sentiment = "Negative"
        else:
            sentiment = "Neutral"
        return {
            "analyzer": self.get_analyzer_name(),
            "sentiment": sentiment,
            "scores": scores,
            "time": time.time() - start_time
        }