from sentence_transformers import SentenceTransformer
from scipy.spatial.distance import cosine
import numpy as np
from sentiment_analyzers.base_analyzer import BaseSentimentAnalyzer
import time

class MPNetAnalyzer(BaseSentimentAnalyzer):
    def __init__(self):
        self.model = SentenceTransformer('all-mpnet-base-v2')
        self.label_texts = ["A negative physician review", "A positive physician review", "A neutral physician review"]
        self.label_embeddings = self.model.encode(self.label_texts)

    def analyze(self, text):
        start_time = time.time()
        # Encode the input text
        text_embedding = self.model.encode([text])[0]

        # Calculate cosine similarities
        similarities = [1 - cosine(text_embedding, label_embedding) for label_embedding in self.label_embeddings]

        # Get the index of the highest similarity
        predicted_index = np.argmax(similarities)

        # Map the index to sentiment
        sentiment = self.label_texts[predicted_index].split()[1].capitalize()
        end_time = time.time()
        return {
            "analyzer": "MPNetAnalyzer",
            "sentiment": sentiment,
            "scores": {
                "negative_similarity": similarities[0],
                "positive_similarity": similarities[1],
                "neutral_similarity": similarities[2]
            },
            "time": end_time - start_time
        }