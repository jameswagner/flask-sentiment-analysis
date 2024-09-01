import logging
import boto3
from flask import request, jsonify, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, Analysis, Result
from database import get_db
from analyzers import get_analyzer_instances
from config import get_config

logger = logging.getLogger(__name__)
cognito_client = boto3.client('cognito-idp')

config = get_config()
COGNITO_CLIENT_ID = config.COGNITO_CLIENT_ID
COGNITO_USER_POOL_ID = config.COGNITO_USER_POOL_ID

def register():
    data = request.json
    username = data['username']
    password = data['password']

    # Register user with AWS Cognito
    try:
        cognito_client.sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=username,
            Password=password,
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': data['email']
                },
            ]
        )
    except cognito_client.exceptions.UsernameExistsException:
        return jsonify({"msg": "Username already exists"}), 400
    except Exception as e:
        logger.error(f"Error during Cognito registration: {str(e)}")
        return jsonify({"msg": "An error occurred during registration"}), 500

    # Add user to local database (without password)
    db = next(get_db())
    try:
        new_user = User(username=username, email=data['email'])
        db.add(new_user)
        db.commit()
        logger.info(f"New user registered: {username}")
        return jsonify({"msg": "User registered successfully"}), 201
    except Exception as e:
        db.rollback()
        logger.error(f"Error during local user registration: {str(e)}")
        return jsonify({"msg": "An error occurred during local user registration"}), 500


def login():
    data = request.json
    username = data['username']
    password = data['password']

    # Authenticate with AWS Cognito
    try:
        response = cognito_client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
            }
        )
        access_token = response['AuthenticationResult']['AccessToken']
        id_token = response['AuthenticationResult']['IdToken']
        refresh_token = response['AuthenticationResult']['RefreshToken']

        logger.info(f"User logged in: {username}")

        # Retrieve the user from the local database
        db = next(get_db())
        user = db.query(User).filter(User.username == username).first()

        if not user:
            return jsonify({"msg": "User not found in local database"}), 404

        # Issue a JWT token for the local session
        local_access_token = create_access_token(identity=user.id)

        return jsonify({
            'local_access_token': local_access_token,
            'cognito_access_token': access_token,
            'id_token': id_token,
            'refresh_token': refresh_token
        }), 200
    except cognito_client.exceptions.NotAuthorizedException:
        logger.warning(f"Failed login attempt for username: {username}")
        return jsonify({"msg": "Bad username or password"}), 401
    except Exception as e:
        logger.error(f"Error during Cognito login: {str(e)}")
        return jsonify({"msg": "An error occurred during login"}), 500
  
def refresh_token():
    data = request.json
    refresh_token = data['refresh_token']

    try:
        response = cognito_client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow='REFRESH_TOKEN_AUTH',
            AuthParameters={
                'REFRESH_TOKEN': refresh_token
            }
        )
        access_token = response['AuthenticationResult']['AccessToken']
        id_token = response['AuthenticationResult']['IdToken']

        return jsonify({
            'cognito_access_token': access_token,
            'id_token': id_token
        }), 200
    except Exception as e:
        logger.error(f"Error during token refresh: {str(e)}")
        return jsonify({"msg": "An error occurred during token refresh"}), 500


def format_result(analyzer_name, **kwargs):
    result = {
        'analyzer': analyzer_name,
        'sentiment': kwargs["sentiment"],
        'additional_data': {}
    }
    for key, value in kwargs.items():
        if key != 'sentiment':
            result['additional_data'][key] = value
    return result

@jwt_required(optional=True)
def analyze():
    current_user = get_jwt_identity()
    data = request.json
    text = data['text']
    
    analyzers = get_analyzer_instances()
    futures = [current_app.executor.submit(analyzer.analyze, text) for analyzer in analyzers]
    
    analysis_results = []
    errored_analyzers = []
    for future, analyzer in zip(futures, analyzers):
        analyzer_class_name = analyzer.__class__.__name__
        try:
            result = future.result()
            display_name = getattr(analyzer, 'display_name', analyzer_class_name)
            formatted_result = format_result(display_name, **result)
            analysis_results.append(formatted_result)
        except Exception as e:
            logger.error(f"Analyzer {analyzer_class_name} failed: {str(e)}")
            errored_analyzers.append(analyzer_class_name)
    
    db = next(get_db())
    new_analysis = Analysis(
        user_id=current_user,
        guest_session_id=request.headers.get('Session-ID') if not current_user else None,
        text=text
    )
    db.add(new_analysis)
    db.flush()
    
    for result in analysis_results:
        new_result = Result(
            analysis_id=new_analysis.id,
            analyzer=result['analyzer'],
            sentiment=result['sentiment'],
            score=result['additional_data'].get('score'),
            additional_data=result['additional_data']
        )
        db.add(new_result)
    
    db.commit()
    logger.info(f"Analysis completed for user: {current_user or 'guest'}. Successful analyzers: {len(analysis_results)}, Failed analyzers: {len(errored_analyzers)}")
    return jsonify({
        "text": text, 
        "results": analysis_results, 
        "successful_analyzers": len(analysis_results),
        "errored_analyzers": errored_analyzers
    })

def get_past_analyses():
    current_user = get_jwt_identity()
    session_id = request.headers.get('Session-ID')
    
    db = next(get_db())
    if current_user:
        analyses = db.query(Analysis).filter(Analysis.user_id == current_user).order_by(Analysis.created_at.desc()).all()
    elif session_id:
        analyses = db.query(Analysis).filter(Analysis.guest_session_id == session_id).order_by(Analysis.created_at.desc()).all()
    else:
        return jsonify([]), 200
    
    results = []
    for analysis in analyses:
        analysis_results = [
            {
                "analyzer": result.analyzer,
                "sentiment": result.sentiment,
                **(result.additional_data or {})
            }
            for result in analysis.results
        ]
        results.append({"text": analysis.text, "results": analysis_results})
    
    logger.info(f"Past analyses retrieved for user: {current_user or 'guest'}")
    return jsonify(results), 200

def health_check():
    return jsonify({'status': 'healthy'})

def register_routes(app):
    app.route('/register', methods=['POST'])(register)
    app.route('/login', methods=['POST'])(login)
    app.route('/analyze', methods=['POST'])(jwt_required(optional=True)(analyze))
    app.route('/past-analyses', methods=['GET'])(jwt_required(optional=True)(get_past_analyses))
    app.route('/health', methods=['GET'])(health_check)