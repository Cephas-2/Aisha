from flask import Flask, request, jsonify, session, redirect, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from datetime import datetime
from flask_cors import CORS
import os

# ----------------- App Config -----------------
app = Flask(__name__)
CORS(app)  

# ⚠️ Never hardcode secrets in production
app.secret_key = "supersecretkey"

# Database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ----------------- Mail Config -----------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "cephascod@gmail.com"

# 🔐 TIP: move this to environment variable later
app.config['MAIL_PASSWORD'] = "biqjmciuzlmo"

mail = Mail(app)

# ----------------- Models -----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship("Post", backref="author", lazy=True)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ----------------- Page Routes -----------------

# Login page
@app.route("/login.html")
def login_page():
    return render_template("login.html")


# Protected Updates Page
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
        return jsonify({"error": "Missing data"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "User already exists"}), 400

    hashed_pw = generate_password_hash(password)

    user = User(email=email, password=hashed_pw)
    db.session.add(user)
    db.session.commit()

    # Admin approval email
    approve_link = f"http://127.0.0.1:5000/approve/{user.id}"

    msg = Message(
        "New User Request",
        sender=app.config['MAIL_USERNAME'],
        recipients=[app.config['MAIL_USERNAME']]
    )

    msg.body = f"""
New user wants access:

Email: {user.email}
Click below to approve:
{approve_link}
"""

    mail.send(msg)

    return jsonify({"message": "Request sent! Waiting for admin approval."})


@app.route("/approve/<int:user_id>")
def approve_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404

    user.is_approved = True
    db.session.commit()

    return f"User {user.email} has been approved!"


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

    return jsonify({"message": "Login success"})


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

    post = Post(user_id=session["user_id"], content=content)
    db.session.add(post)
    db.session.commit()

    return jsonify({"message": "Post created"})


@app.route("/api/posts", methods=["GET"])
def get_posts():
    posts = Post.query.order_by(Post.created_at.desc()).all()

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
