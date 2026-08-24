"""
SentinelClip — Flask API Hub Entrypoint

The Flask API is the SINGLE source of truth for the database.
No other component writes to SQLite directly.

Binds to 127.0.0.1:5000 ONLY — never 0.0.0.0.
CORS restricted to localhost and the browser extension origin.
"""

import os
from flask import Flask, g
from flask_cors import CORS
from api.db import get_db, init_db
from api.auth import get_or_create_admin_token
from api.routes.policy_routes import policy_bp
from api.routes.log_routes import log_bp
from api.routes.event_routes import event_bp


def create_app(db_path: str = None) -> Flask:
    """
    Flask application factory.
    
    Args:
        db_path: Optional database path override (for testing).
    """
    app = Flask(__name__)

    # Store db_path in app config for access in request context
    if db_path:
        app.config["DB_PATH"] = db_path

    # CORS — restricted to localhost and extension
    # NOTE: Replace EXTENSION_ID_HERE with your actual extension ID after loading
    CORS(app, origins=[
        "http://127.0.0.1:*",
        "http://localhost:*",
        "chrome-extension://EXTENSION_ID_HERE",
    ])

    # Register blueprints
    app.register_blueprint(policy_bp)
    app.register_blueprint(log_bp)
    app.register_blueprint(event_bp)

    # Database lifecycle
    @app.before_request
    def before_request():
        g.db = get_db(app.config.get("DB_PATH"))

    @app.teardown_request
    def teardown_request(exception):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    # Initialize database on first request
    with app.app_context():
        conn = get_db(app.config.get("DB_PATH"))
        init_db(conn)
        conn.close()

    # Ensure admin token exists
    get_or_create_admin_token()

    return app


if __name__ == "__main__":
    app = create_app()
    print("\n" + "=" * 60)
    print("  SentinelClip API Hub")
    print("  Listening on http://127.0.0.1:5000")
    print("=" * 60 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
