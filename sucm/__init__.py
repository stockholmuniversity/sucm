from flask import Flask
from flask_sso import SSO

from . import sucm_routes
from .sucm_automation import start_scheduler
from .sucm_settings import cfg


def create_app():
    secretKey = cfg.get("SUCM", "secret_key")

    app = Flask(__name__)
    app.secret_key = secretKey
    SSO(app=app)

    app.register_blueprint(sucm_routes.bp)
    start_scheduler()

    return app
