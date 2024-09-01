from importlib import import_module

class AnalyzerConfig:
    def __init__(self, class_name, module_name):
        self.class_name = class_name
        self.module_name = module_name
        self.instance = None

    def initialize(self):
        module = import_module(f'sentiment_analyzers.{self.module_name}')
        analyzer_class = getattr(module, self.class_name)
        self.instance = analyzer_class()

ANALYZER_CONFIGS = [
    AnalyzerConfig('GPTZeroShotAnalyzer', 'gpt_zero_shot_analyzer'),
    AnalyzerConfig('VaderAnalyzer', 'vader_analyzer'),
    AnalyzerConfig('TextBlobAnalyzer', 'textblob_analyzer'),
    AnalyzerConfig('MPNetAnalyzer', 'mpnet_analyzer'),
    AnalyzerConfig('MNLIAnalyzer', 'mnli_analyzer'),
    AnalyzerConfig('TinyBERTAnalyzer', 'tinybert_analyzer'),
]

def initialize_analyzers():
    for config in ANALYZER_CONFIGS:
        config.initialize()

def get_analyzer_instances():
    return [config.instance for config in ANALYZER_CONFIGS if config.instance]

def get_analyzer_class_name(display_name):
    for config in ANALYZER_CONFIGS:
        if hasattr(config.instance, 'display_name') and config.instance.display_name == display_name:
            return config.class_name
    return display_name  # Fallback to display_name if not found
