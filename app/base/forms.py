# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask_wtf import FlaskForm
from wtforms import TextField, PasswordField, SelectField, SubmitField, StringField
from wtforms.validators import InputRequired, Email, DataRequired

## login and registration

class LoginForm(FlaskForm):
    username = TextField    ('Username', id='username_login'   , validators=[DataRequired()])
    password = PasswordField('Password', id='pwd_login'        , validators=[DataRequired()])

class CreateAccountForm(FlaskForm):
    username = TextField('Username'     , id='username_create' , validators=[DataRequired()])
    password = PasswordField('Password' , id='pwd_create'      , validators=[DataRequired()])

class ResetPasswordForm(FlaskForm):
    username_reset = TextField('Username'     , id='username_reset' , validators=[DataRequired()])
    pwd_login = PasswordField('Password' , id='pwd_login'      , validators=[DataRequired()])
    pwd_confirm = PasswordField('PasswordConfirm' , id='pwd_confirm'      , validators=[DataRequired()])

class NewMissionForm(FlaskForm):
    bot = SelectField(u'Bot', id='bot', validators=[DataRequired()])

    address = StringField('Address', id='address', validators=[DataRequired()])
    city = StringField('City' , id='city', validators=[DataRequired()])
    zipcode = StringField('ZIP Code' , id='zipcode', validators=[DataRequired()])
    submit = SubmitField('Create Mission' , id='new_mission', validators=[DataRequired()])
