from flask import Flask, request, jsonify, session, redirect, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from datetime import datetime
from flask_cors import CORS
from dotenv import load_dotenv
import secrets
import re
import os

load_dotenv()

# ----------------- App Config -----------------

app = Flask(__name__)
CORS(app)

app.secret_key = os.getenv("SECRET_KEY")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,   # True in production with HTTPS
    SESSION_COOKIE_SAMESITE="Lax"
)

# ----------------- Database -----------------

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ----------------- Mail -----------------

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")

mail = Mail(app)

# ----------------- Models -----------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    is_approved = db.Column(db.Boolean, default=False)
    approval_token = db.Column(db.String(200), unique=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    posts = db.relationship("Post", backref="author", lazy=True)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    content = db.Column(db.Text, nullable=False)

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

# ----------------- Helpers -----------------

def valid_email(email):
    pattern = r"^[^@]+@[^@]+\.[^@]+$"
    return re.match(pattern, email)

# ----------------- Page Routes -----------------

@app.route("/login.html")
def login_page():
    return render_template("login.html")


@app.route("/updates")
def updates_page():

    if not session.get("user_id"):
        return redirect("/login.html")

    return render_template("updates.html")

# ----------------- Auth Routes -----------------

@app.route("/signup", methods=["POST"])
def signup():

    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400

    if not valid_email(email):
        return jsonify({"error": "Invalid email"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "User already exists"}), 400

    hashed_pw = generate_password_hash(password)

    token = secrets.token_urlsafe(32)

    user = User(
        email=email,
        password=hashed_pw,
        approval_token=token
    )

    db.session.add(user)
    db.session.commit()

    approve_link = f"http://127.0.0.1:5000/approve/{token}"

    msg = Message(
        "New User Approval Request",
        sender=app.config['MAIL_USERNAME'],
        recipients=[app.config['MAIL_USERNAME']]
    )

    msg.body = f"""
New user signup request

Email: {email}

Approve user here:
{approve_link}
"""

    mail.send(msg)

    return jsonify({
        "message": "Signup successful. Waiting for admin approval."
    })


@app.route("/approve/<token>")
def approve_user(token):

    user = User.query.filter_by(approval_token=token).first()

    if not user:
        return "Invalid approval token", 404

    user.is_approved = True
    user.approval_token = None

    db.session.commit()

    return f"User {user.email} approved successfully"


@app.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    if not check_password_hash(user.password, password):
        return jsonify({"error": "Incorrect password"}), 401

    if not user.is_approved:
        return jsonify({"error": "Waiting for admin approval"}), 403

    session["user_id"] = user.id

    return jsonify({"message": "Login successful"})


@app.route("/logout")
def logout():

    session.pop("user_id", None)

    return redirect("/login.html")

# ----------------- Post APIs -----------------

@app.route("/api/posts", methods=["POST"])
def create_post():

    if not session.get("user_id"):
        return jsonify({"error": "Not logged in"}), 403

    data = request.get_json()
    content = data.get("content")

    if not content:
        return jsonify({"error": "Post cannot be empty"}), 400

    post = Post(
        user_id=session["user_id"],
        content=content
    )

    db.session.add(post)
    db.session.commit()

    return jsonify({"message": "Post created"})


@app.route("/api/posts", methods=["GET"])
def get_posts():

    posts = Post.query.order_by(
        Post.created_at.desc()
    ).all()

    return jsonify([
        {
            "id": p.id,
            "content": p.content,
            "user_email": p.author.email,
            "created_at": p.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }
        for p in posts
    ])

# ----------------- Run App -----------------

if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(debug=True)