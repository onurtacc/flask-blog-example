from flask import Flask, render_template, flash, redirect, url_for, session, logging, request, g
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import sqlite3

DATABASE = './db.sqlite3'
app = Flask(__name__)
app.secret_key = "flask_blog"


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("Please login", "danger")
            return redirect(url_for("login"))

    return decorated_function


class RegisterForm(Form):
    name = StringField("Name Surname", validators=[validators.Length(min=4, max=25), validators.DataRequired()])
    username = StringField("Username", validators=[validators.Length(min=5, max=35), validators.DataRequired()])
    email = StringField("E-mail", validators=[validators.Email(message="Please enter a valid email address")])
    password = PasswordField("Password", validators=[
        validators.DataRequired("Please define a password"),
        validators.EqualTo(fieldname="confirm", message="password does not match")
    ])
    confirm = PasswordField("Verify password")


class LoginForm(Form):
    username = StringField("Username")
    password = PasswordField("Password")


class ArticleForm(Form):
    title = StringField("Article Title", validators=[validators.Length(min=5, max=100)])
    content = TextAreaField("Article Content", validators=[validators.Length(min=10)])


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/articles")
def articles():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    cursor = db.cursor()

    query = "SELECT * FROM articles"

    cursor.execute(query)
    data = cursor.fetchall()
    if data:
        return render_template("articles.html", articles=data)

    return render_template("articles.html")


@app.route("/dashboard")
@login_required
def dashboard():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    query = "SELECT * FROM articles where author=?"
    cursor.execute(query, (session["username"],))
    data = cursor.fetchall()
    if data:
        return render_template("dashboard.html", articles=data)
    return render_template("dashboard.html")


@app.route("/add-article", methods=["GET", "POST"])
@login_required
def add_article():
    form = ArticleForm(request.form)
    if request.method == "POST" and form.validate():
        title = form.title.data
        content = form.content.data

        db = sqlite3.connect(DATABASE)
        cursor = db.cursor()

        query = "INSERT INTO articles(title, author, content) VALUES (?,?,?)"
        cursor.execute(query, (title, session["username"], content))
        db.commit()
        cursor.close()
        flash("Article successfully added", "success")
        db.close()
        return redirect(url_for("dashboard"))

    return render_template("add-article.html", form=form)


@app.route("/delete/<string:article_id>")
@login_required
def delete_article(article_id):
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()

    query = "SELECT * FROM articles where author=? and id=?"
    cursor.execute(query, (session["username"], article_id))
    data = cursor.fetchone()
    if data:
        query_2 = "DELETE FROM articles where id=?"
        cursor.execute(query_2, (article_id,))
        db.commit()
        cursor.close()
        return redirect(url_for("dashboard"))
    else:
        flash("No such article, or you are not authorized to delete this article.", "danger")
        return redirect(url_for("index"))


@app.route("/edit/<string:article_id>", methods=["GET", "POST"])
@login_required
def update_article(article_id):
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    if request.method == "GET":
        query = "SELECT * FROM articles where id=? and author=?"
        cursor.execute(query, (article_id, session["username"]))
        data = cursor.fetchone()
        if data:
            form = ArticleForm()
            form.title.data = data["title"]
            form.content.data = data["content"]
            return render_template("update.html", form=form)
        else:
            flash("No such article, or you are not authorized to delete this article.", "danger")
            return redirect(url_for("index"))
    else:
        form = ArticleForm(request.form)
        new_title = form.title.data
        new_content = form.content.data
        query = "UPDATE articles SET title=?, content=? where id=?"

        cursor.execute(query, (new_title, new_content, article_id))
        db.commit()
        flash("Article successfully updated", "success")
        return redirect(url_for("dashboard"))


@app.route("/article/<string:article_id>")
def article(article_id):
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    query = "SELECT * FROM articles where id=?"
    cursor.execute(query, (article_id,))
    data = cursor.fetchone()

    if data:
        return render_template("article.html", article=data)
    else:
        return render_template("article.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        name = form.name.data
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(form.password.data)

        db = sqlite3.connect(DATABASE)
        cursor = db.cursor()
        query = "INSERT INTO users(name, email, username, password) VALUES (?,?,?,?)"

        cursor.execute(query, (name, email, username, password))
        db.commit()
        cursor.close()

        flash("You have successfully registered", "success")
        db.close()
        return redirect(url_for("login"))
    else:
        return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if request.method == "POST" and form.validate():
        username = form.username.data
        password_entered = form.password.data

        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        query = "SELECT * FROM users where username=?"

        cursor.execute(query, (username,))
        data = cursor.fetchone()

        if data:
            real_password = data["password"]
            if sha256_crypt.verify(password_entered, real_password):
                cursor.close()
                flash("You have successfully logged in", "success")
                db.close()

                session["logged_in"] = True
                session["username"] = username

                return redirect(url_for("index"))
            else:
                cursor.close()
                flash("Wrong Password", "danger")
                db.close()
                return redirect(url_for("login"))
        else:
            cursor.close()
            flash("This user doesn't exist", "danger")
            db.close()
            return redirect(url_for("login"))

    else:
        return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
