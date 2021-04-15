# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask import Flask, url_for, json, request
from flask_login import LoginManager, current_user, login_user
from flask_sqlalchemy import SQLAlchemy
from importlib import import_module
from logging import basicConfig, DEBUG, getLogger, StreamHandler
from os import path

db = SQLAlchemy()
login_manager = LoginManager()

def register_extensions(app):
    db.init_app(app)
    login_manager.init_app(app)

def register_blueprints(app):
    for module_name in ('base', 'webauthn'):
        module = import_module('app.{}.routes'.format(module_name))
        app.register_blueprint(module.blueprint)

def configure_database(app):

    @app.before_first_request
    def initialize_database():
        db.create_all()

    @app.teardown_request
    def shutdown_session(exception=None):
        db.session.remove()

def create_app(config):
    app = Flask(__name__, static_folder='base/static')
    app.config.from_object(config)
    register_extensions(app)
    register_blueprints(app)
    configure_database(app)

    @app.context_processor
    def inject_global_config():
        return dict(v=config)

    @app.before_request
    def auth_iap():
        if not current_user.is_authenticated:
            iap_header = request.headers.get('X-Goog-Authenticated-User-Email', '')
            prefix = 'accounts.google.com:'
            if len(iap_header) and iap_header.startswith(prefix) > 0:
                app.logger.info('IAP header present: X-Goog-Authenticated-User-Email:%s', iap_header)
                from app.base.models import User
                username = iap_header[len(prefix):]
                user = User.query.filter_by(username=username).first()
                if not user:
                    user = User(
                        username = username,
                        password = 'google_iap'
                    )
                    db.session.add(user)
                    db.session.commit()
                login_user(user)
                app.logger.info('%s logged in successfully through IAP', username)
        return 
    
    return app
