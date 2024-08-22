from flask import Flask, jsonify, redirect, request, url_for
from flask_oidc import OpenIDConnect
from flask_cors import CORS
from functools import wraps
from okta_jwt_verifier import AccessTokenVerifier
import os
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

app.config.update({
    'SECRET_KEY': os.environ.get('FLASK_SECRET_KEY') or os.urandom(24),
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'flask-demo',
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
})

oidc = OpenIDConnect(app)

# Configure the AccessTokenVerifier
access_token_verifier = AccessTokenVerifier(
    issuer='https://aw.oktapreview.com/oauth2/aus8b7ctvoWY32cl31d7',
    audience='api://tvdsadsv'  # This should match the audience in your Okta application settings
)

def verify_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"detail": "Authorization header is missing"}), 401
        
        try:
            token = auth_header.split(" ")[1]
            logger.debug(f"Attempting to verify token: {token[:10]}...")  # Log first 10 chars of token
            
            # Verify the token with Okta
            access_token_verifier.verify(token)
            
            logger.info("Token verification successful")
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Token verification failed: {str(e)}")
            return jsonify({"detail": f"Invalid or expired token: {str(e)}"}), 401
    return decorated

def dual_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            # Token-based authentication
            return verify_token(f)(*args, **kwargs)
        elif oidc.user_loggedin:
            # Redirect-based authentication
            logger.info("User authenticated via OIDC")
            return f(*args, **kwargs)
        else:
            logger.info("User not authenticated, redirecting to login")
            return redirect(url_for('login'))
    return decorated

@app.route('/api/data')
@dual_auth_required
def api_data():
    return jsonify({'data': 'This is protected data'})

@app.route('/')
def home():
    return "Welcome to the Dual Auth Demo!"

@app.route('/login')
@oidc.require_login
def login():
    return redirect(url_for('api_data'))

@app.route('/logout')
def logout():
    oidc.logout()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)


    