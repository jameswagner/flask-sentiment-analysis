# gpt_analyzer.py

from sentiment_analyzers.base_analyzer import BaseSentimentAnalyzer
from openai import OpenAI
from tenacity import retry, wait_random_exponential, stop_after_attempt
import time
import boto3
import json

class GPTZeroShotAnalyzer(BaseSentimentAnalyzer):
    def __init__(self):
      secret_name = "openai"
      region_name = "us-east-1"
      session = boto3.session.Session()
      client = session.client(
        service_name='secretsmanager',
        region_name=region_name
      )
      get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
      )
      self.api_key = json.loads(get_secret_value_response['SecretString'])[secret_name]
      print(f"api key: {self.api_key}")
      self.client = OpenAI(api_key=self.api_key)
      self.model = "gpt-3.5-turbo"
      self.scoring_prompt = """Rate the sentiment of the following physician review on a scale from 0 to 10, where:
0 is extremely negative
5 is neutral
10 is extremely positive

Here's the review:

[DOCUMENT]

Please respond with only a number between 0 and 10.

Assistant: """

    @retry(wait=wait_random_exponential(min=1, max=60), stop=stop_after_attempt(6))
    def gpt_prediction(self, document):
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": self.scoring_prompt.replace("[DOCUMENT]", document)}
        ]

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0
        )
        return response.choices[0].message.content.strip()

    def analyze(self, text):
        start_time = time.time()
        raw_score = float(self.gpt_prediction(text))
        end_time = time.time()
        
        if raw_score < 4:
            sentiment = "Negative"
        elif raw_score > 6:
            sentiment = "Positive"
        else:
            sentiment = "Neutral"

        return {
            "analyzer": "GPTAnalyzer",
            "sentiment": sentiment,
            "raw_score": raw_score,
            "time": end_time - start_time
        }