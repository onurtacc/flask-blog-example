from flask import Flask, render_template, flash, redirect, url_for, session, logging, request, g
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
import sqlite3


# User register form
class RegisterForm(Form):
    name = StringField("Name Surname", validators=[validators.Length(min=4, max=25), validators.DataRequired()])
    username = StringField("Username", validators=[validators.Length(min=5, max=35), validators.DataRequired()])
    email = StringField("E-mail", validators=[validators.Email(message="Please enter a valid email address")])
    password = PasswordField("Password", validators=[
        validators.DataRequired("Please define a password"),
        validators.EqualTo(fieldname="confirm", message="password does not match")
    ])
    confirm = PasswordField("Verify password")


DATABASE = './db.sqlite3'
app = Flask(__name__)
app.secret_key = "flask_blog"


@app.route("/")
def index():
    return render_template("index.html", answer="yes")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        db = sqlite3.connect(DATABASE)
        name = form.name.data
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(form.password.data)
        cursor = db.cursor()
        query = "INSERT INTO users(name, email, username, password) VALUES (?,?,?,?)"
        cursor.execute(query, (name, email, username, password))
        db.commit()
        cursor.close()
        flash("You have successfully registered", "success")
        db.close()
        return redirect(url_for("index"))
    else:
        return render_template("register.html", form=form)


if __name__ == "__main__":
    app.run(debug=True)
