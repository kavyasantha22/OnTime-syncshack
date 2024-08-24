import os

import sqlite3
from flask import Flask, flash, redirect, render_template, request, session
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

# Configure CS50 Library to use SQLite database
OnTimeDB = sqlite3.connect('ontime.db')
OnTimeCursor = OnTimeDB.cursor()


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
    """Show portfolio of stocks"""
    
    groups = OnTimeCursor.execute("SELECT * FROM groups WHERE person_id = ?", session["user_id"])
    schedules = OnTimeCursor.execute("SELECT * FROM schedules WHERE person_id = ?", session["user_id"])
    
    # for stock in stocks:
    #     stock["price"] = lookup(stock["stock_name"])["price"]
    #     stock["total"] = stock["price"]*stock["shares"]
    user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]
    return render_template("index.html", groups=groups, schedules=schedules, user = user)

@app.route("/upload-photo", methods=["GET", "POST"])
@login_required
def upload_photo():
    task = OnTimeCursor.execute("""
            SELECT * FROM schedules 
            WHERE person_id = ? 
            AND task_status = 0 
            ORDER BY task_time DESC 
            LIMIT 1
        """, (session["user_id"],)).fetchone()
    if request.method == "POST":
        OnTimeCursor.execute("""
            UPDATE schedules
            SET task_status = 1
            WHERE person_id = ? AND task_name = ? AND task_time = ?
        """, (session["user_id"], task["task_name"], task["task_time"]))
        OnTimeDB.commit()
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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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

        check = db.execute("SELECT username FROM users WHERE username = ?", username)
        print("#"*30, check)
        if check != []:
            return apology("username has been taken", 400)

        hash = generate_password_hash(password)
        # Query database for username
        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)", username, hash
        )
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")



    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form["symbol"]
        stock_info = lookup(symbol)
        if not stock_info:
            return apology("invalid stock symbol", 403)
        user_amount = db.execute(
            "SELECT shares FROM stock_ownership WHERE person_id = ? and stock_name = ?", session["user_id"], symbol)[0]["shares"]

        try:
            amount = int(request.form.get("shares"))
            if amount <= 0:
                return apology("number of shares must be positive", 400)
            if amount > user_amount:
                return apology("number of shares exceed yours", 400)
        except ValueError:
            return apology("number of shares must be an integer", 400)

        price = stock_info["price"]
        total = price * amount
        print(total)

        # Query the user's current cash
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        print(cash)

        # Check if the user has enough cash to buy

        # Update the user's cash
        cash += total

        # Update user's stock amount
        user_amount -= amount
        db.execute("UPDATE stock_ownership SET shares = ? WHERE person_id = ? and stock_name = ?",
                   user_amount, session["user_id"], symbol)

        # Insert to activity
        current_time = datetime.datetime.now(pytz.timezone(
            "US/Eastern")).strftime('%Y-%m-%d %H:%M:%S')
        db.execute("INSERT INTO activity (person_id, stock_name, buy_sell, shares_amount, price, date) VALUES (?, ?, ?, ?, ?, ?)",
                   session["user_id"], symbol, 'sell', amount, price, current_time)

        # Update the user's cash in the users table
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])

        return redirect("/")
    else:
        stocks = db.execute("SELECT * FROM stock_ownership WHERE person_id = ?", session["user_id"])
        print(stocks)
        return render_template("sell.html", stocks=stocks)
