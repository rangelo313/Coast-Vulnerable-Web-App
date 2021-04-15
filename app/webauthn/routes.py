from flask import Blueprint

import os
import sys
import datetime

import app.webauthn.util as util
import webauthn

from flask import flash
from flask import jsonify
from flask import make_response
from flask import redirect
from flask import request
from flask import session
from flask import url_for
from flask_login import login_required

from app import db

from flask_login import current_user
from decouple import config
from app.base.models import User, SecurityKey

blueprint = Blueprint(
    'webauthn_blueprint',
    __name__,
    url_prefix='/webauthn',
    template_folder='templates',
    static_folder='static'
)

TRUST_ANCHOR_DIR = 'trusted_attestation_roots'

@blueprint.route('/begin_activate', methods=['POST'])
@login_required
def webauthn_begin_activate():

    if request.form.get('master_password', '') != config('MASTER_PASSWORD'):
        return 'forbidden', 403

    challenge = util.generate_challenge(32)
    ukey = util.generate_ukey()

    username = current_user.get_id()
    display_name = current_user.username

    make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
        challenge, 
        config('RP_NAME'), 
        config('RP_ID'), 
        ukey, 
        username, 
        display_name,
        config('ORIGIN'))

    # We strip the saved challenge of padding, so that we can do a byte
    # comparison on the URL-safe-without-padding challenge we get back
    # from the browser.
    # We will still pass the padded version down to the browser so that the JS
    # can decode the challenge into binary without too much trouble.

    resp = make_response(jsonify(make_credential_options.registration_dict))
    resp.set_cookie('challenge', challenge.rstrip('='))
    resp.set_cookie('register_ukey', ukey)

    return resp


@blueprint.route('/begin_assertion', methods=['POST'])
def webauthn_begin_assertion():
    user_id = request.form.get('user_id')
    challenge = util.generate_challenge(32)

    if not util.validate_username(user_id):
        return make_response(jsonify({'fail': 'Invalid user_id.'}), 401)

    user = User.query.filter_by(id=user_id).first()
    username = user.username

    if not user:
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)

    security_keys = SecurityKey.query.filter_by(user_id=user_id).all()

    webauthn_users = []

    for sk in security_keys:
        webauthn_users.append(webauthn.WebAuthnUser(
        sk.ukey, user_id, username, '',
        sk.credential_id, sk.pub_key, sk.sign_count, sk.rp_id))

    if len(webauthn_users) == 0:
        return make_response(jsonify({'fail': 'No security keys associated with this user.'}), 401)

    webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(webauthn_users, challenge)

    resp = make_response(jsonify(webauthn_assertion_options.assertion_dict))
    resp.set_cookie('challenge', challenge.rstrip('='))
    return resp


@blueprint.route('/verify_credential_info', methods=['POST'])
def webauthn_verify_credential_info():
    challenge = request.cookies.get('challenge', '')
    ukey = request.cookies.get('register_ukey', '')

    username = current_user.username
    display_name = current_user.username

    registration_response = request.form
    trust_anchor_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), TRUST_ANCHOR_DIR)
    trusted_attestation_cert_required = False
    self_attestation_permitted = True
    none_attestation_permitted = True

    webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
        config('RP_ID'),
        config('ORIGIN'),
        registration_response,
        challenge,
        trust_anchor_dir,
        trusted_attestation_cert_required,
        self_attestation_permitted,
        none_attestation_permitted,
        uv_required=False)  # User Verification

    try:
        webauthn_credential = webauthn_registration_response.verify()
    except Exception as e:
        return jsonify({'fail': 'Registration failed. Error: {}'.format(e)})

    # compatibility fix
    cid = webauthn_credential.credential_id
    if not isinstance(cid, str):
        cid = cid.decode('utf-8')

    new_key = SecurityKey(
        user_id = current_user.get_id(),
        ukey = ukey,
        credential_id=cid,
        pub_key=webauthn_credential.public_key,
        sign_count=webauthn_credential.sign_count,
        rp_id=config('RP_ID'),
        name = 'some key',
        date_added = datetime.date.today()
    )

    db.session.add(new_key)
    db.session.commit()

    flash('Successfully registered as {}.'.format(username))

    return jsonify({'success': 'User successfully registered.'})


@blueprint.route('/verify_assertion', methods=['POST'])
def webauthn_verify_assertion():
    challenge = request.cookies.get('challenge')
    assertion_response = request.form
    credential_id = assertion_response.get('id')

    sk = SecurityKey.query.filter_by(credential_id=credential_id).first()

    if not sk:
        return make_response(jsonify({'fail': 'Credential does not exist.'}), 401)

    user = User.query.filter_by(id=sk.user_id).first()

    webauthn_user = webauthn.WebAuthnUser(
        sk.ukey, sk.user_id, user.username, '',
        sk.credential_id, sk.pub_key, sk.sign_count, sk.rp_id)

    webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
        webauthn_user,
        assertion_response,
        challenge,
        config('ORIGIN'),
        uv_required=False)  # User Verification

    try:
        sign_count = webauthn_assertion_response.verify()
    except Exception as e:
        return jsonify({'fail': 'Assertion failed. Error: {}'.format(e)})

    # Update counter.
    user.sign_count = sign_count
    db.session.add(user)
    db.session.commit()

    session['verified'] = datetime.datetime.now().timestamp()
    return_url = session.pop('return_url', '/')

    return jsonify({
        'success': 'Successfully authenticated as {}'.format(user.username),
        'return_url': return_url
    })
