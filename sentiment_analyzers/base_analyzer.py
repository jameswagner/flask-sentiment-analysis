from abc import ABC, abstractmethod

class BaseSentimentAnalyzer(ABC):
    @abstractmethod
    def analyze(self, text):
        pass

    @classmethod
    def get_analyzer_name(cls):
        return cls.__name__