import os
from datetime import timedelta

from dotenv import load_dotenv
from secrets_manager import get_secret
import boto3
import logging

logger = logging.getLogger(__name__)

class Config:
    def __init__(self):
        if os.getenv('FLASK_ENV') != 'production':
          print("Loading environment variables from .env file")
          load_dotenv(verbose=True)
        else:
          print("Running in production mode, using system environment variables")

        self.SECRET_KEY = os.getenv('SECRET_KEY', 'fallback-secret-key')
        self.JWT_SECRET_KEY = get_secret('jwt_secret_key')
        self.JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=int(os.getenv('JWT_EXPIRATION_MINUTES', 60)))
        
        self.SESSION_TYPE = os.getenv('SESSION_TYPE', 'filesystem')
        logger.info(f"SESSION_TYPE set to: {self.SESSION_TYPE}")
        
        self.MAX_WORKERS = int(os.getenv('MAX_WORKERS', 5))
        self.LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
        self.COGNITO_CLIENT_ID = os.getenv('COGNITO_CLIENT_ID')
        self.COGNITO_USER_POOL_ID = os.getenv('COGNITO_USER_POOL_ID')

        db_credentials = self.get_db_credentials()
        self.DATABASE_URI = f"postgresql://{db_credentials['username']}:{db_credentials['password']}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
        
        logger.info(f"Configuration loaded: DATABASE_URI = {self.DATABASE_URI}")

        self.ANALYZERS = [
            'GPTZeroShotAnalyzer',
            'VaderAnalyzer',
            'TextBlobAnalyzer',
            'MPNetAnalyzer',
            'MNLIAnalyzer',
            'TinyBERTAnalyzer'
        ]

    @staticmethod
    def get_db_credentials():
        if os.getenv('FLASK_ENV') == 'production':
            # Use AWS Secrets Manager in production
            client = boto3.client('secretsmanager')
            secret = client.get_secret_value(SecretId=os.getenv('DB_SECRETS_ARN'))
            return eval(secret['SecretString'])
        else:
            # Use environment variables for local testing
            return {
                'username': os.getenv('DB_USERNAME'),
                'password': os.getenv('DB_PASSWORD')
            }


_config = Config()

# Function to get the singleton instance
def get_config():
    print(f"get_config called {_config.DATABASE_URI}")
    return _config