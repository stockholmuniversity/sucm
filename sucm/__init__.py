from flask import Flask, session
from flask_sso import SSO
from flask_wtf import CSRFProtect

from . import sucm_routes
from .sucm_acme_routes import bp as acme_accounts_bp
from .sucm_acme_server_routes import bp as acme_server_bp
from .sucm_automation import start_scheduler
from .sucm_settings import cfg
from .sucm_version import get_version_info


def create_app():
    secretKey = cfg.get("SUCM", "secret_key")

    app = Flask(__name__)
    app.secret_key = secretKey
    SSO(app=app)

    # Session cookie hardening (defense-in-depth against CSRF/session theft).
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = True  # app is served over HTTPS only

    # CSRF protection for all cookie/session-authenticated POST forms. The
    # ACME wire-protocol blueprint (/acme/...) is exempt: it is authenticated
    # by JWS/EAB signatures, not cookies/sessions, so CSRF does not apply.
    csrf = CSRFProtect(app)
    csrf.exempt(acme_server_bp)

    app.register_blueprint(sucm_routes.bp)
    app.register_blueprint(acme_accounts_bp)
    app.register_blueprint(acme_server_bp)
    start_scheduler()

    version_info = get_version_info()

    @app.context_processor
    def inject_roles():
        return {
            "current_roles": session.get("roles", []),
            "version_info": version_info,
        }

    @app.after_request
    def set_security_headers(response):
        # Content-Security-Policy: scripts/styles load from self plus the
        # CDNs used by base.html (jQuery/Bootstrap) ; inline <style> blocks
        # require style-src 'unsafe-inline'. Nothing loads from other origins.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://code.jquery.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'"
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response

    return app
