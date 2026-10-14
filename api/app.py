"""
SentinelClip — Flask API Hub Entrypoint

The Flask API is the SINGLE source of truth for the database.
No other component writes to SQLite directly.

Binds to SENTINELCLIP_HOST (default 0.0.0.0 for LAN fleet mode).
Configure the firewall to allow port 5000 only from the local subnet.
CORS is restricted to configured local origins and the browser extension.
"""

import os
from flask import Flask, g
from flask_cors import CORS
from api.db import get_db, init_db
from api.auth import get_or_create_admin_token
from api.routes.policy_routes import policy_bp
from api.routes.log_routes import log_bp
from api.routes.event_routes import event_bp
from api.routes.device_routes import device_bp


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
    app.register_blueprint(device_bp)

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
    host = os.getenv("SENTINELCLIP_HOST", "0.0.0.0")
    port = int(os.getenv("SENTINELCLIP_PORT", "5000"))
    print("\n" + "=" * 60)
    print("  SentinelClip API Hub")
    print(f"  Listening on http://{host}:{port}")
    print("  Configure the firewall to restrict this port to the local subnet.")
    print("=" * 60 + "\n")
    app.run(host=host, port=port, debug=True)
