#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User


class ClearSession(Resource):
    """Clears session data like page_views and user_id for logout or reset."""
    def delete(self):
        session['page_views'] = None
        session['user_id'] = None
        return {}, 204


class Signup(Resource):
    """
    POST /signup: Creates new user. Model's password_hash SETTER automatically hashes!
    Sets session and returns user data.
    """
    def post(self):
        json_data = request.get_json()
        username = json_data.get('username')
        password = json_data.get('password')

        if username is None or password is None:
            return {'error': 'Missing username or password'}, 400

        # Check for existing user
        existing_user = User.query.filter(User.username == username).first()
        if existing_user:
            return {'error': 'Username already taken'}, 400

        # Model's SETTER automatically hashes password!
        user = User(username=username)
        user.password_hash = password  # Triggers bcrypt hashing in setter
        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id
        return user.to_dict(), 201


class Checksession(Resource):
    """GET /check_session: Returns authenticated user or 204 empty."""
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {}, 204

        user = db.session.get(User, user_id)
        if user is None:
            session['user_id'] = None
            return {}, 204

        return user.to_dict(), 200


class Login(Resource):
    """
    POST /login: Uses model's EXACT authenticate() method!
    1. Find user by username
    2. Call user.authenticate(password) - accesses _password_hash safely
    3. Set session on success
    """
    def post(self):
        json_data = request.get_json()
        username = json_data.get('username')
        password = json_data.get('password')

        if username is None or password is None:
            return {'error': 'Missing credentials'}, 400

        # Find user first
        user = User.query.filter(User.username == username).first()

        # authenticate method (bypasses protected getter)
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        else:
            session.pop('user_id', None)
            return {'error': 'Invalid username or password'}, 401


class Logout(Resource):
    """DELETE /logout: Clears session completely."""
    def delete(self):
        session.clear()
        return {}, 204


# Exact route registration for tests
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(Checksession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)