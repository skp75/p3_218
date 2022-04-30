import logging
import os.path
import pandas as pd
from io import StringIO
import csv
from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.auth.decorators import admin_required
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from app.auth.forms import login_form, register_form, profile_form, security_form, user_edit_form, csv_form
from app.db import db
from app.db.models import User

auth = Blueprint('auth', __name__, template_folder='templates')
from flask import current_app

@auth.route('/login', methods=['POST', 'GET'])
def login():
    form = login_form()
    if current_user.is_authenticated:
        return redirect(url_for('auth.dashboard'))
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('auth.login'))
        else:
            user.authenticated = True
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("Welcome", 'success')
            return redirect(url_for('auth.dashboard'))
    return render_template('login.html', form=form)





@auth.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('auth.dashboard'))
    form = register_form()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            user = User(email=form.email.data, password=generate_password_hash(form.password.data))
            db.session.add(user)
            db.session.commit()
            if user.id == 1:
                user.is_admin = 1
                db.session.add(user)
                db.session.commit()
            flash('Congratulations, you are now a registered user!', "success")
            return redirect(url_for('auth.login'), 302)
        else:
            flash('Already Registered')
            return redirect(url_for('auth.login'), 302)
    return render_template('register.html', form=form)


@auth.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    log = logging.getLogger("myApp")
    form = csv_form()
    if form.validate_on_submit():
        file = form.file
        raw_data = pd.read_csv(file.data)
        raw_data = drop_bad_data(raw_data)
        flash(raw_data)

    return render_template('dashboard.html', form=form)

'''Removes un-needed data from table'''
def drop_bad_data(raw_data):
    raw_data.drop('Spotify ID', inplace=True, axis=1)
    raw_data.drop('Artist IDs', inplace=True, axis=1)
    raw_data.drop('Album Name', inplace=True, axis=1)
    raw_data.drop('Duration (ms)', inplace=True, axis=1)
    raw_data.drop('Popularity', inplace=True, axis=1)
    raw_data.drop('Added By', inplace=True, axis=1)
    raw_data.drop('Added At', inplace=True, axis=1)
    raw_data.drop('Danceability', inplace=True, axis=1)
    raw_data.drop('Energy', inplace=True, axis=1)
    raw_data.drop('Key', inplace=True, axis=1)
    raw_data.drop('Loudness', inplace=True, axis=1)
    raw_data.drop('Mode', inplace=True, axis=1)
    raw_data.drop('Speechiness', inplace=True, axis=1)
    raw_data.drop('Acousticness', inplace=True, axis=1)
    raw_data.drop('Instrumentalness', inplace=True, axis=1)
    raw_data.drop('Liveness', inplace=True, axis=1)
    raw_data.drop('Valence', inplace=True, axis=1)
    raw_data.drop('Tempo', inplace=True, axis=1)
    raw_data.drop('Time Signature', inplace=True, axis=1)
    return raw_data

@auth.route("/logout")
@login_required
def logout():
    """Logout the current user."""
    user = current_user
    user.authenticated = False
    db.session.add(user)
    db.session.commit()
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/users')
@login_required
@admin_required
def browse_users():
    data = User.query.all()
    titles = [('email', 'Email'), ('registered_on', 'Registered On')]
    retrieve_url = ('auth.retrieve_user', [('user_id', ':id')])
    edit_url = ('auth.edit_user', [('user_id', ':id')])
    add_url = url_for('auth.add_user')
    delete_url = ('auth.delete_user', [('user_id', ':id')])

    current_app.logger.info("Browse page loading")

    return render_template('browse.html', titles=titles, add_url=add_url, edit_url=edit_url, delete_url=delete_url,
                           retrieve_url=retrieve_url, data=data, User=User, record_type="Users")


@auth.route('/users/<int:user_id>')
@login_required
def retrieve_user(user_id):
    user = User.query.get(user_id)
    return render_template('profile_view.html', user=user)


@auth.route('/users/<int:user_id>/edit', methods=['POST', 'GET'])
@login_required
def edit_user(user_id):
    user = User.query.get(user_id)
    form = user_edit_form(obj=user)
    if form.validate_on_submit():
        user.about = form.about.data
        user.is_admin = int(form.is_admin.data)
        db.session.add(user)
        db.session.commit()
        flash('User Edited Successfully', 'success')
        return redirect(url_for('auth.browse_users'))
    return render_template('user_edit.html', form=form)


@auth.route('/users/new', methods=['POST', 'GET'])
@login_required
def add_user():
    form = register_form()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            user = User(email=form.email.data, password=generate_password_hash(form.password.data))
            db.session.add(user)
            db.session.commit()
            flash('Congratulations, you just created a user', 'success')
            return redirect(url_for('auth.browse_users'))
        else:
            flash('Already Registered')
            return redirect(url_for('auth.browse_users'))
    return render_template('user_new.html', form=form)


@auth.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user.id == current_user.id:
        flash("You can't delete yourself!")
        return redirect(url_for('auth.browse_users'), 302)
    db.session.delete(user)
    db.session.commit()
    flash('User Deleted', 'success')
    return redirect(url_for('auth.browse_users'), 302)


@auth.route('/profile', methods=['POST', 'GET'])
def edit_profile():
    user = User.query.get(current_user.get_id())
    form = profile_form(obj=user)
    if form.validate_on_submit():
        user.about = form.about.data
        db.session.add(current_user)
        db.session.commit()
        flash('You Successfully Updated your Profile', 'success')
        return redirect(url_for('auth.dashboard'))
    return render_template('profile_edit.html', form=form)


@auth.route('/account', methods=['POST', 'GET'])
def edit_account():
    user = User.query.get(current_user.get_id())
    form = security_form(obj=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.password = form.password.data
        db.session.add(current_user)
        db.session.commit()
        flash('You Successfully Updated your Password or Email', 'success')
        return redirect(url_for('auth.dashboard'))
    return render_template('manage_account.html', form=form)
