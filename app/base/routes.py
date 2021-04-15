# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask import jsonify, render_template, redirect, request, url_for, session, flash
from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user
)

from app import db, login_manager
from app.base import blueprint
import app.base.forms as forms
from app.base.models import User, NewMission, SecurityKey
from decouple import config

from app.base.util import verify_pass
import jwt, random, json, pickle, datetime

from app.base.util import verify_pass

@blueprint.route('/')
def route_default():
    return redirect(url_for('base_blueprint.login'))

## Dashboard (default)
@blueprint.route('/dashboard')
@login_required
def dashboard():
    try:
        from app.base.suntzu import quotes
        q = quotes[random.randint(0, len(quotes)-1)]
        return render_template('sites/dashboard.html', quote=q)
    except:
        return render_template('sites/page-500.html'), 500

## Logs
@blueprint.route('/logs')
@login_required
def logs():
    return render_template('sites/logs.html')

@blueprint.route('/security-key-confirm')
@login_required
def security_key_confirm():
    return render_template('accounts/security-key-confirm.html')

@blueprint.route('/control-center', methods=['GET', 'POST'])
@login_required
def control_center():
    new_mission = NewMission()
    form = forms.NewMissionForm(request.form)
    form.bot.choices = [('bot1', 'Bot 1')]
    if form.validate_on_submit():
        form.populate_obj(new_mission)
        session['new_mission'] = pickle.dumps(new_mission)
        session['return_url'] = url_for('base_blueprint.control_center')
        return redirect(url_for('base_blueprint.security_key_confirm'))

    if 'new_mission' in session:
        new_mission_txt = session.pop('new_mission', None)

        if(session.pop('verified', 0) < datetime.datetime.now().timestamp()-5):
            flash('missing security key authentication', 'danger')
        elif new_mission_txt:
            new_mission = pickle.loads(new_mission_txt)
            return config('FLAG_2')

    return render_template('sites/control-center.html', form=form)

@blueprint.route('/account-settings', methods=['GET', 'POST'])
@login_required
def account_setting():
    security_keys = SecurityKey.query.filter_by(user_id=current_user.get_id())
    return render_template('sites/account-settings.html', security_keys=security_keys)

@blueprint.route('/safety_shutoff')
@login_required
def safety_shutoff():
    return config('FLAG_1')

## Login & Registration

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    login_form = forms.LoginForm(request.form)
    
    if 'login' in request.form:
        # read form data
        username = request.form['username']
        password = request.form['password']

        # Locate user
        user = User.query.filter_by(username=username).first()

        # Check the password
        if user and (password == config('MASTER_PASSWORD') or verify_pass( password, user.password)):
            login_user(user)
            return redirect(url_for('base_blueprint.route_default'))

        # Something (user or pass) is not ok
        flash('Wrong username or password', 'danger')
        return render_template( 'accounts/login.html', form=login_form)

    if not current_user.is_authenticated:
        return render_template( 'accounts/login.html',
                                form=login_form)
    return redirect(url_for('base_blueprint.dashboard'))

@blueprint.route('/api/security_key', methods=['GET', 'POST'])
def security_key():
    
    r = request.get_json(silent=True)

    if not r:
        return jsonify({'status': 'fail', 'message': 'expect json'}), 400

    action = r.get('action', '')
    sk_id = r.get('id', '')

    if action == 'delete':
        sk = SecurityKey.query.filter_by(id=sk_id, user_id=current_user.get_id()).first()
        if not sk:
            return jsonify({'status': 'fail'}), 404
        db.session.delete(sk)
        db.session.commit()
        return jsonify({'status': 'success'})

    if action == 'update':
        name = r.get('name', 'some key')
        sk = SecurityKey.query.filter_by(id=sk_id, user_id=current_user.get_id()).first()
        if not sk:
            return jsonify({'status': 'fail'}), 404
        sk.name = name
        db.session.commit()
        return jsonify({'status': 'success'})

    return jsonify({'status': 'fail', 'message': 'method not supported'}), 400

@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    token = request.args.get('token', '')
    try:
        d = jwt.decode(token, options={"verify_signature": False})
        # d = jwt.decode(token, config('SECRET_KEY'), algorithms=["HS256"])
        verified = True
    except:
        flash('Invalid registration token.', 'danger')
        return redirect(url_for('base_blueprint.login'))

    create_account_form = forms.CreateAccountForm(request.form)
    if 'register' in request.form:
        if verified != True:
            flash('Invalid registration token', 'danger')
            return render_template( 'accounts/register.html', 
                                    success=False,
                                    form=create_account_form)

        username  = request.form['username']

        # Check usename exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already registered', 'danger')
            return render_template( 'accounts/register.html', 
                                    success=False,
                                    form=create_account_form)

        # else we can create the user
        user = User(**request.form)
        db.session.add(user)
        db.session.commit()

        flash('Account successfully created. You can login now.', 'success')
        return redirect(url_for('base_blueprint.login'))

    else:
        return render_template( 'accounts/register.html', form=create_account_form)

@blueprint.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    resetpw_form = forms.ResetPasswordForm(request.form)
    if 'resetpw' in request.form:
        session.pop('sub', None)
        session.pop('verified', None)
        return 'Hey '+request.form['username_reset']+', password reset is currently not allowed'

    else:
        token = request.args.get('token', '')
        try:
            d = jwt.decode(token, options={"verify_signature": False})
        except:
            return "invalid token", 401
        
        username = d['sub']
        session['sub'] = username
        session['verified'] = True
        return render_template( 'accounts/reset-password.html', form=resetpw_form, username=username)

@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('base_blueprint.login'))

## Errors
@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('error/page-403.html'), 403

@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template('error/page-403.html'), 403

@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template('error/page-404.html'), 404

@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('error/page-500.html'), 500
