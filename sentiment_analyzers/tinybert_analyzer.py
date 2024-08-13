from .base_analyzer import BaseSentimentAnalyzer
from transformers import AutoModelForSequenceClassification, AutoTokenizer, Trainer, TrainingArguments
from datasets import Dataset
import time

class TinyBERTAnalyzer(BaseSentimentAnalyzer):
    def __init__(self):
        
        self.model_path = "sentiment_analyzers/tinybert_model"
        self.model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
        self.model = self.model.to('cpu')

        
        # Load tokenizer from the original model name
        self.tokenizer = AutoTokenizer.from_pretrained("sentiment_analyzers/tinybert_tokenizer")
        
        # Set up a simple TrainingArguments
        self.training_args = TrainingArguments(
            output_dir="./results",
            do_train=False,
            do_predict=True,
        )
        
        # Initialize the Trainer
        self.trainer = Trainer(
            model=self.model,
            args=self.training_args,
        )

    def analyze(self, text):
        start_time = time.time()
        # Tokenize the input
        
        predict_dataset = Dataset.from_dict({"text": [text]})
        predict_dataset = predict_dataset.map(lambda examples: self.tokenizer(examples["text"], padding=True, truncation=True, max_length=128), batched=True)
        outputs = self.trainer.predict(predict_dataset)
        logits = outputs.predictions[0]
        
        # Convert logits to probabilities
        import numpy as np
        probabilities = np.exp(logits) / np.sum(np.exp(logits), axis=-1, keepdims=True)
        predicted_class = np.argmax(probabilities)
        confidence = probabilities[predicted_class]

        sentiment = "Positive" if predicted_class == 1 else "Negative"
        end_time = time.time()
        return {
            "analyzer": "TinyBERTAnalyzer",
            "sentiment": sentiment,
            "confidence": float(confidence),
            "time": end_time - start_time
        }