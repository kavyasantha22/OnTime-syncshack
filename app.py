import sqlite3
from flask import Flask, redirect, flash, render_template, request, session, g
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required

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
    cursor = get_cursor()

    # Fetch all data
    groups = cursor.execute(
        "SELECT * FROM groups WHERE person_id = ?", (session["user_id"],)).fetchall()
    schedules = cursor.execute(
        "SELECT * FROM schedules WHERE person_id = ?", (session["user_id"],)).fetchall()
    user = cursor.execute("SELECT * FROM users WHERE id = ?",
                          (session["user_id"],)).fetchone()
    task = cursor.execute("""
            SELECT * FROM schedules 
            WHERE person_id = ? 
            AND task_status = 0 
            ORDER BY task_time DESC 
            LIMIT 1
        """, (session["user_id"],)).fetchone()

    # Handle task update
    if request.method == "POST":
        cursor.execute("""
            UPDATE schedules
            SET task_status = 1
            WHERE person_id = ? AND task_name = ? AND task_time = ?
        """, (session["user_id"], task["task_name"], task["task_time"]))
        g.db.commit()
        return redirect("/")
    else:
        print("#" * 30)
        for schedule in schedules:
            print(schedule["task_name"])
        # for group in groups:
        #     print()
        return render_template("index.html", groups=groups, schedules=schedules, user=user, task=task)


@app.route("/add-task", methods=["GET", "POST"])
@login_required
def add_task():
    cursor = get_cursor()

    if request.method == "POST":
        task_name = request.form.get("task_name")
        date = request.form.get("task_date")
        time = request.form.get("task_time")

        if not task_name or not date or not time:
            return apology("Fill everything", 403)

        task_time_str = f"{date} {time}:00"
        task_time = datetime.strptime(task_time_str, "%Y-%m-%d %H:%M:%S")
        print("#"*30, task_time)
        cursor.execute(
            "INSERT INTO schedules (person_id, task_name, task_time, task_status) VALUES (?, ?, ?, ?)",
            (session["user_id"], task_name, task_time, 0)
        )

        g.db.commit()

        flash(f"Task '{task_name}' scheduled for {task_time_str}")
        return redirect("/")
    else:
        return render_template("add-task.html")


@app.route("/add-group", methods=["GET", "POST"])
@login_required
def add_group():
    cursor = get_cursor()

    if request.method == "POST":

        group_name = request.form.get("group_name")

        # Check if the group exists
        rows = cursor.execute(
            "SELECT * FROM groups WHERE group_name = ?", (group_name,)
        ).fetchone()

        if rows is None:
            return apology("Invalid group name", 403)

        # If the group exists, insert the user into the group
        cursor.execute(
            "INSERT INTO groups (group_id, person_id, group_name, group_description) VALUES (?, ?, ?, ?)",
            (rows["group_id"], session["user_id"],
             rows["group_name"], rows["group_description"])
        )
        g.db.commit()

        return redirect("/add-group")
    else:
        return render_template("add-group.html")


@app.route("/create-group", methods=["GET", "POST"])
@login_required
def create_group():
    cursor = get_cursor()

    if request.method == "POST":
        group_name = request.form.get("group_name")
        group_desc = request.form.get("group_desc")

        if not group_name:
            return apology("must provide group name", 403)

        cursor.execute(
            "INSERT INTO groups (person_id, group_name, group_description) VALUES (?, ?, ?)", (
                session["user_id"], group_name, group_desc)
        )
        g.db.commit()

        return redirect("/")
    else:
        return render_template("create-group.html")


@app.route("/group/<int:group_id>", methods=["GET", "POST"])
@login_required
def group(group_id):
    cursor = get_cursor()

    # Fetch group details based on group_id
    group = cursor.execute(
        "SELECT * FROM groups WHERE group_id = ?", (group_id,)).fetchone()

    people = cursor.execute("""
        SELECT users.* FROM users
        JOIN user_groups ON users.id = user_groups.user_id
        WHERE user_groups.group_id = ?
        """, (group_id,)).fetchall()

    if group is None:
        return apology("Group not found", 404)

    return render_template(f"group{group_id}.html", group=group, people=people)


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

        check = cursor.execute(
            "SELECT username FROM users WHERE username = ?", (username,)).fetchone()
        print("#"*30, check)
        if check != None:
            return apology("username has been taken", 400)

        hash = generate_password_hash(password)
        # Query database for username
        cursor.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)", (username, hash)
        )
        g.db.commit()
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")
