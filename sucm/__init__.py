from flask import Flask
from flask_sso import SSO
from .sucn_settings import cfg
from . import sucm_routes

def create_app():
    secretKey = cfg.get("SUCM", "secret_key")

    app = Flask(__name__)
    app.secret_key = secretKey
    SSO(app=app)

    app.register_blueprint(sucm_routes.bp)

    return app
