import os
import time
import secrets
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from models import db, Nonce, User
from eth_account.messages import encode_defunct
from eth_account import Account
import jwt
from flask_cors import CORS
from functools import wraps

# ───────────────────────────────────────────────
# Load environment variables
# ───────────────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))

FLASK_SECRET = os.getenv("FLASK_SECRET", "dev_secret")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///auth.db")
NONCE_TTL = int(os.getenv("NONCE_TTL_SECONDS", "300"))
JWT_EXP = int(os.getenv("JWT_EXP_SECONDS", "3600"))

# ───────────────────────────────────────────────
# Flask app factory
# ───────────────────────────────────────────────
def create_app():
    app = Flask(__name__)
    CORS(
    app,
    resources={r"/*": {"origins": ["http://127.0.0.1:8000"]}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS"]
)

    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = FLASK_SECRET

    db.init_app(app)

    # ───────────────────────────────────────────────
    # Routes
    # ───────────────────────────────────────────────
    @app.route('/')
    def index():
        return jsonify({'ok': True, 'message': 'wallet-2fa backend running'})

    @app.route('/auth/nonce', methods=['GET'])
    def get_nonce():
        n = secrets.token_urlsafe(32)
        entry = Nonce(nonce=n)
        db.session.add(entry)
        db.session.commit()
        return jsonify({'nonce': n, 'expires_in': NONCE_TTL})

    @app.route('/auth/verify', methods=['POST'])
    def verify():
        """
        Expected JSON:
        {
          "address": "0xabc...",
          "signature": "0x...",
          "nonce": "previously fetched nonce"
        }
        """
        data = request.get_json(force=True, silent=True) or {}
        address = data.get('address')
        signature = data.get('signature')
        nonce = data.get('nonce')

        if not (address and signature and nonce):
            return jsonify({'error': 'missing address/signature/nonce'}), 400

        entry = Nonce.query.filter_by(nonce=nonce).first()
        if not entry:
            return jsonify({'error': 'invalid nonce'}), 400
        if entry.used:
            return jsonify({'error': 'nonce already used'}), 400
        if int(time.time()) - entry.created_at > NONCE_TTL:
            return jsonify({'error': 'nonce expired'}), 400

        message = encode_defunct(text=nonce)
        try:
            recovered = Account.recover_message(message, signature=signature)
        except Exception as e:
            return jsonify({'error': 'invalid signature', 'detail': str(e)}), 400

        if recovered.lower() != address.lower():
            return jsonify({'error': 'signature does not match address'}), 400

        entry.used = True
        db.session.commit()

        user = User.query.filter_by(address=address.lower()).first()
        if not user:
            user = User(address=address.lower())
            db.session.add(user)
            db.session.commit()

        now = int(time.time())
        payload = {
            'sub': address.lower(),
            'iat': now,
            'exp': now + JWT_EXP,
            'nonce': nonce
        }
        token = jwt.encode(payload, FLASK_SECRET, algorithm='HS256')
        return jsonify({'token': token, 'expires_in': JWT_EXP})

    # ───────────────────────────────────────────────
    # JWT Authentication decorator
    # ───────────────────────────────────────────────
    def token_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            if "Authorization" in request.headers:
                bearer = request.headers["Authorization"]
                token = bearer.split(" ")[1] if " " in bearer else bearer

            if not token:
                return jsonify({"error": "token missing"}), 401

            try:
                data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
                request.wallet_address = data["sub"]
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "token expired"}), 401
            except Exception as e:
                return jsonify({"error": f"invalid token: {str(e)}"}), 401

            return f(*args, **kwargs)
        return decorated

    # ───────────────────────────────────────────────
    # Protected route
    # ───────────────────────────────────────────────
    @app.route("/protected")
    @token_required
    def protected():
        return jsonify({
            "ok": True,
            "message": f"Hello, {request.wallet_address}! You accessed a protected route."
        })
    # ───────────────────────────────────────────────
    # Token refresh route
    # ───────────────────────────────────────────────
    @app.route("/auth/refresh", methods=["POST"])
    @token_required
    def refresh():
        now = int(time.time())
        new_payload = {
            'sub': request.wallet_address,
            'iat': now,
            'exp': now + JWT_EXP
        }
        new_token = jwt.encode(new_payload, app.config["SECRET_KEY"], algorithm="HS256")
        return jsonify({'token': new_token, 'expires_in': JWT_EXP})


    return app


# ───────────────────────────────────────────────
# Dev entry point
# ───────────────────────────────────────────────
if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1', port=5000, debug=True)
