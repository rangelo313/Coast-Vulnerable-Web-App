# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask_login import UserMixin
from sqlalchemy import Column, Integer, String

from app import db, login_manager

from app.base.util import hash_pass

class User(db.Model, UserMixin):

    __tablename__ = 'User'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)

    def __init__(self, **kwargs):
        for property, value in kwargs.items():
            # depending on whether value is an iterable or not, we must
            # unpack it's value (when **kwargs is request.form, some values
            # will be a 1-element list)
            if hasattr(value, '__iter__') and not isinstance(value, str):
                # the ,= unpack of a singleton fails PEP8 (travis flake8 test)
                value = value[0]

            if property == 'password':
                value = hash_pass( value )
                
            setattr(self, property, value)

    def __repr__(self):
        return str(self.username)

class SecurityKey(db.Model):

    __tablename__ = 'SecurityKey'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'))

    ukey = db.Column(db.String(20), unique=True, nullable=False)
    credential_id = db.Column(db.String(250), unique=True, nullable=False)
    pub_key = db.Column(db.String(65), unique=True, nullable=True)
    sign_count = db.Column(db.Integer, default=0)
    rp_id = db.Column(db.String(253), nullable=False)

    name = db.Column(db.String(20), nullable=False)
    date_added = db.Column(db.Date(), nullable=False)

    def __repr__(self):
        return '<Security Key %r from user %r>' % (self.id, self.user_id)

class NewMission():
    bot = None
    address = None
    city = None
    zipcode = None

@login_manager.user_loader
def user_loader(id):
    return User.query.filter_by(id=id).first()

@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = User.query.filter_by(username=username).first()
    return user if user else None
