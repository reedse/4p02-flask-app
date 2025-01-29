# For Login page, signup page and sign out function
from flask import Blueprint, render_template, request, flash, redirect, url_for, request

# for db
from .models import User
from . import db  ##means from __init__.py import db

# import from flash_login to hash password, securely storing password intead of storing them in  in plain text
# converting password  to something more secure (hash -> does not have an inverse )
# hash password, basically can only check the entered password == to the hash(password) not the way around
from werkzeug.security import generate_password_hash, check_password_hash

# you can not access the home page unless yourre logged in
# these import are the reeason why for UserMixer in the models.py so that we can use the current_user object to access the current user
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint("auth", __name__)


# route to /login
@auth.route("/login", methods=["GET", "POST"])
def login():
    # when user click login button(POST), then we retrieve data from email and password field
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # check if the usr email was sent to us is valid, query db to check user data (usr email) then return the first one that match
        user = User.query.filter_by(email=email).first()
        # if usr exists
        if user:
            if check_password_hash(user.password, password):
                # remember=true for flask is to remember user login unless the user clear the browsing history (sesssion) or flask server restart
                flash("Logged in successfully!", category="success")
                login_user(user, remember=True)
                # redirect to homepage
                return redirect(url_for("views.home"))
            # if the password is wrong
            else:
                flash("Incorrect password, try again", category="error")
        else:
            flash("email does not exist", category="error")
    # direct user to the login page
    return render_template("login.html", user=current_user)


# route to sign up page
@auth.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    # handling post request when click submit 'POST' for form data (email, firstname, password1, password2)
    if request.method == "POST":
        email = request.form.get("email")
        first_name = request.form.get("firstName")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        # check if the user has already existed
        user = User.query.filter_by(email=email).first()
        if user:
            flash("Email already exists", category="error")
            return render_template("sign_up.html", user=current_user)
        # some conditions
        if len(email) < 4:
            # basically alert the users that something went wrong, basically when these condition is met
            flash("Email must be greater than 3 characters.", category="error")
        elif len(first_name) < 2:
            flash("First name  must be greater than 1 character.", category="error")
        elif password1 != password2:
            flash("Passwords don't match", category="error")
        elif len(password1) < 7:
            flash("Passwords must be at least 7 characters", category="error")
        else:
            # add user to db
            # sha256 hashing algo for password
            new_user = User(
                email=email,
                first_name=first_name,
                password=generate_password_hash(password1, method="pbkdf2:sha256"),
            )
            # add newly created user to database
            db.session.add(new_user)
            # add and then commit(update)
            db.session.commit()
            # remember=true for flask is to remember user login unless the user clear the browsing history (sesssion) or flask server restart
            login_user(new_user, remember=True)
            flash("Account created!", category="success")
            # then redirect to the hompage
            return redirect(url_for("views.home"))

    return render_template("sign_up.html", user=current_user)


@auth.route("/logout")
# decorator -> make sure that we cannot acces the  def logout() or root /logout unless the user is logged_in, basically we not be able to logout if we not login
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
