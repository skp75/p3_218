from flask_login import login_user, login_required, logout_user, current_user
from app.db import db
from app.db.models import User

"""This test the homepage"""

from app.auth import login

def test_request_main_menu_links(client):
    """This makes the index page"""
    response = client.get("/")
    assert response.status_code == 200
    assert b'href="/login"' in response.data
    assert b'href="/register"' in response.data

def test_auth_pages(client):
    """This makes the index page"""
    response = client.get("/dashboard")
    assert response.status_code == 302
    response = client.get("/register")
    assert response.status_code == 200
    response = client.get("/login")
    assert response.status_code == 200

def test_dashboard_deny(client):
    response = client.get("/dashboard")
    assert response.status_code == 302


def test_dashboard_accept(client):
    # user = User.query.filter_by('johncena@gmail.com')
    # if not User.is_authenticated():
    #     db.session.add(user)
    #     db.session.commit()
    #     login_user(user)
    login()
    response = client.get("/dashboard")
    assert response.status_code == 200