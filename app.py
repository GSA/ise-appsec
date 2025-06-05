import hashlib
import os
import sqlite3
from pathlib import Path

from flask import Flask, request, g, make_response
# from flask_api import status
from dataclasses import dataclass

_DATABASE = "user.db"

# test comment

@dataclass
class User:
    id: int
    username: str
    pw_hash: str


def create_flask_app() -> Flask:
    app = Flask(__name__)
    with app.app_context():
        pass
    return app


def get_user_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(_DATABASE)
    return db


app = create_flask_app()


def init_db():
    create_user_schema_sql = """
    DROP TABLE IF EXISTS user;
    CREATE TABLE user(
        user_id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT NOT NULL, 
        pw_hash TEXT NOT NULL
    );
    """
    with app.app_context():
        connection = get_user_db()
        connection.cursor().executescript(create_user_schema_sql)
        connection.commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def _hash(value: str) -> str:
    m = hashlib.sha1()
    m.update(value.encode('utf-8'))
    return m.hexdigest()


def add_user(username: str, password: str):
    pw_hash = _hash(password)
    return _add_user(get_user_db(), username, pw_hash)


def _add_user(con: sqlite3.Connection, username: str, pw_hash: str):
    res = con.cursor().execute("INSERT INTO user (username, pw_hash) VALUES (?, ?) RETURNING *;",
                               (username, pw_hash))
    (res_id, res_username, res_pw_hash) = res.fetchone()
    con.commit()
    user = User(res_id, res_username, res_pw_hash)
    return user


def get_authenticated_user(username: str, password: str) -> User:
    pw_hash = _hash(password)
    # return _get_authenticated_user(get_user_db(), username, pw_hash)
    return _bad_get_authenticated_user(get_user_db(), username, pw_hash)

def _get_authenticated_user(con, username: str, pw_hash: str) -> User:
    res = con.cursor().execute("""
        SELECT user_id, username, pw_hash FROM user WHERE username = ? AND pw_hash = ? ;
        """, (username, pw_hash))
    row = res.fetchone()
    if row is not None:
        (res_id, res_username, res_pw_hash) = row
        return User(res_id, res_username, res_pw_hash)
    else:
        raise ValueError("Could not authenticate user.")

def _bad_get_authenticated_user(con, username: str, pw_hash: str):
    vulnerable_raw_sql ="SELECT user_id, username, pw_hash FROM user WHERE username = '" + username + "' AND pw_hash = '" + pw_hash + "';"
    print(f"Executing vulnerable raw SQL:\n{vulnerable_raw_sql}")
    res = con.cursor().execute(vulnerable_raw_sql)
    row = res.fetchone()
    if row is not None:
        (res_id, res_username, res_pw_hash) = row
        return User(res_id, res_username, res_pw_hash)
    else:
        raise ValueError("Could not authenticate user.")


def _print_users():
    res = get_user_db().cursor().execute("SELECT * FROM user;")
    for row in res.fetchall():
        print(row)


@app.route('/user', methods=["POST"])
def create_user():  # put application's code here
    username: str = request.form["username"]
    password: str = request.form["password"]
    user = add_user(username, password)
    return {"id": user.id, "username": user.username}


@app.route("/user/login", methods=["POST"])
def login_user():
    username: str = request.form["username"]
    password: str = request.form["password"]
    # Vulnerability: mishandling secrets, disclosing sensitive information
    print(f"Logging in user: {username} password: {password}")
    try:
        user = get_authenticated_user(username, password)
        res = make_response({"id": user.id, "username": user.username})
        res.status_code = 200
        # Vulnerability: using insecure cookie to hold auth info
        res.set_cookie(key="authenticated", value="true", secure=False, httponly=False)
        return res
    except ValueError as e:
        return {"error": "Authentication Failed"}, 401


@app.route("/", methods=["GET"])
def hello_world():
    _print_users()
    return "Hello World!", 200


if __name__ == '__main__':
    try:
        app.run()
    finally:
        with app.app_context():
            db = get_user_db()
            if db is not None:
                db.close()
