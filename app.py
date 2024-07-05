import os
import datetime

from helpers import apology, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from flask_mysqldb import MySQL
import MySQLdb.cursors

app = Flask(__name__)

# Configure to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Database connection
app.config["MYSQL_DB"] = "mealplanner"

db = MySQL(app)


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    # Clear old users
    session.clear()

    if request.method == "POST":
        # Check for username/password
        if not request.form.get("username"):
            return apology("Please provide username", 403)
        if not request.form.get("password"):
            return apology("Please provide a password", 403)

        # Check valid username/password
        username = request.form.get("username")
        password = request.form.get("password")
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username))
        if len(cursor) != 1 or not check_password_hash(cursor[0]["hash"], password):
            return apology(
                "Invalid username/password combination. Please validate your username and password and try again.",
                403,
            )

        # Keep userid in session
        session["user_id"] = cursor[0]["id"]

        # Redirect to home page
        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Check required fields
        if not request.form.get("username"):
            return apology("Please provide username", 403)
        if not request.form.get("email"):
            return apology("Please provide email address", 403)
        if not request.form.get("password"):
            return apology("Please provide a password", 403)
        if not request.form.get("confirm"):
            return apology("Please confirm your password", 403)

        password = request.form.get("password")
        confirm = request.form.get("confirm")

        if passoword != confirm:
            return apology("Passwords do not match", 403)

        # Check if username already exists. If unique, insert into database
        rows = db.execute(
            "SELECT * FROM users WHERE username = %s", request.form.get("username")
        )
        if len(rows) == 1:
            return apology("Username already exists. Please choose another.", 403)
        elif len(rows) == 0:
            db.execute(
                "INSERT INTO users (username, hash, email) VALUES (%s, %s, %s)",
                request.form.get("username"),
                generate_password_hash(password),
                request.form.get("email"),
            )

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
