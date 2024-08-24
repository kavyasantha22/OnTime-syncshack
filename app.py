import os

import sqlite3
from flask import Flask, flash, redirect, render_template, request, session, g
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
import pytz

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Database setup with g (Flask global context)
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('ontime.db')
        g.db.row_factory = sqlite3.Row  # To access columns by name
    return g.db

def get_cursor():
    db = get_db()
    return db.cursor()

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response



@app.route("/")
@login_required
def index():
    print(1)
    """Show portfolio of stocks"""
    cursor = get_cursor()
    groups = cursor.execute("SELECT * FROM groups WHERE person_id = ?", (session["user_id"],))
    schedules = cursor.execute("SELECT * FROM schedules WHERE person_id = ?", (session["user_id"],))
    
    user = cursor.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template("index.html", groups=groups, schedules=schedules, user = user)

@app.route("/upload-photo", methods=["GET", "POST"])
@login_required
def upload_photo():
    cursor = get_cursor()
    task = cursor.execute("""
            SELECT * FROM schedules 
            WHERE person_id = ? 
            AND task_status = 0 
            ORDER BY task_time DESC 
            LIMIT 1
        """, (session["user_id"],)).fetchone()
    if request.method == "POST":
        cursor.execute("""
            UPDATE schedules
            SET task_status = 1
            WHERE person_id = ? AND task_name = ? AND task_time = ?
        """, (session["user_id"], task["task_name"], task["task_time"]))
        g.db.commit()
        return redirect("/")
    else:
        return render_template("upload_photo.html", task=task)
        
@app.route("/group", methods = ["GET", "POST"])
@login_required
def group():
    pass

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    cursor = get_cursor()
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        username = request.form.get("username")
        rows = cursor.execute(
            "SELECT * FROM users WHERE username = ?", (username, )
        ).fetchone()
        print("#"*30)
        print("Row Keys:", rows.keys())
        # Ensure username exists and password is correct
        if rows is None or not check_password_hash(
            rows["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    cursor = get_cursor()
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        elif not confirmation:
            return apology("must confirm password", 400)

        if password != confirmation:
            return apology("password and confirmed password must be identical", 400)

        check = cursor.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
        print("#"*30, check)
        if check != None:
            return apology("username has been taken", 400)

        hash = generate_password_hash(password)
        # Query database for username
        cursor.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)", (username, hash)
        )
        g.db.commit(    )
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")
