from datetime import UTC, datetime
import logging
import uuid
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
GUEST_USERNAME = config.GUEST_USERNAME
GUEST_PASSWORD = config.GUEST_PASSWORD

def register():
    data = request.json
    username = data['username']
    password = data['password']

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

def _authenticate_with_cognito(username, password):
    try:
        response = cognito_client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
            }
        )
        return response['AuthenticationResult']
    except cognito_client.exceptions.NotAuthorizedException:
        logger.warning(f"Failed login attempt for username: {username}")
        return None
    except Exception as e:
        logger.error(f"Error during Cognito authentication: {str(e)}")
        raise
      
def _create_login_response(auth_result, user_id=None, guest_session_id=None):
    if guest_session_id:
        user_data = {
            'user_type': 'guest',
            'guest_session_id': guest_session_id
        }
    else:
        user_data = {
            'user_type': 'registered',
            'id': user_id
        }
    local_access_token = create_access_token(user_data)
    return jsonify({
        'local_access_token': local_access_token,
        'cognito_access_token': auth_result['AccessToken'],
        'id_token': auth_result['IdToken'],
        'refresh_token': auth_result['RefreshToken'],
        'guest_session_id': guest_session_id  # Include this for guest logins
    }), 200

def login():
    data = request.json
    is_guest = data.get('is_guest', False)

    if is_guest:
        username = GUEST_USERNAME
        password = GUEST_PASSWORD
        guest_session_id = str(uuid.uuid4())
        print(f"Guest login username: {username}, guest_session_id: {guest_session_id}")
    else:
        username = data['username']
        password = data['password']
        guest_session_id = None

    try:
        auth_result = _authenticate_with_cognito(username, password)
        if not auth_result:
            return jsonify({"msg": "Bad username or password"}), 401

        if not is_guest:
            db = next(get_db())
            user = db.query(User).filter(User.username == username).first()
            if not user:
                return jsonify({"msg": "User not found in local database"}), 404
            user_id = user.id
        else:
            user_id = None

        print(f"{'Guest' if is_guest else 'User'} logged in: {username}")
        return _create_login_response(auth_result, user_id, guest_session_id)
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
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

@jwt_required()
def analyze():
    current_user = get_jwt_identity()
    print(f"current_user: {current_user}")
    user_type = current_user['user_type']
    
    if user_type == 'guest':
        guest_session_id = current_user['guest_session_id']
        user_id = None
    else:
        user_id = current_user['id']
        guest_session_id = None
    
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
        user_id=user_id,
        guest_session_id=guest_session_id,
        text=text,
        user_type=user_type,
        created_at=datetime.now(UTC)
    )
    print(new_analysis)
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
    print(f"Analysis completed for {'guest' if user_type == 'guest' else 'user'}: {guest_session_id or user_id}. Successful analyzers: {len(analysis_results)}, Failed analyzers: {len(errored_analyzers)}")
    return jsonify({
        "text": text, 
        "results": analysis_results, 
        "successful_analyzers": len(analysis_results),
        "errored_analyzers": errored_analyzers
    })

@jwt_required()
def get_past_analyses():
    current_user = get_jwt_identity()
    user_type = current_user['user_type']
    
    db = next(get_db())
    if user_type == 'guest':
        guest_session_id = current_user['guest_session_id']
        analyses = db.query(Analysis).filter(Analysis.guest_session_id == guest_session_id).order_by(Analysis.created_at.desc()).all()
    else:
        user_id = current_user['id']
        analyses = db.query(Analysis).filter(Analysis.user_id == user_id).order_by(Analysis.created_at.desc()).all()
    
    results = []
    for analysis in analyses:
        print(analysis.text)
        print(analysis.created_at)
        analysis_results = [
            {
                "analyzer": result.analyzer,
                "sentiment": result.sentiment,
                **(result.additional_data or {})
            }
            for result in analysis.results
        ]
        results.append({"text": analysis.text, "results": analysis_results})
    
    logger.info(f"Past analyses retrieved for {'guest' if user_type == 'guest' else 'user'}: {guest_session_id if user_type == 'guest' else user_id}")
    return jsonify(results), 200

def health_check():
    return jsonify({'status': 'healthy'})

def register_routes(app):
    app.route('/register', methods=['POST'])(register)
    app.route('/login', methods=['POST'])(login)
    app.route('/analyze', methods=['POST'])(jwt_required()(analyze))
    app.route('/past-analyses', methods=['GET'])(jwt_required()(get_past_analyses))
    app.route('/health', methods=['GET'])(health_check)