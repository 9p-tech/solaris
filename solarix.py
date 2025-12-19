from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import libsql_experimental as libsql

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)


TURSO_DATABASE_URL = "libsql://pranav-9p-tech.aws-ap-south-1.turso.io"
TURSO_AUTH_TOKEN = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3NjYwOTc5ODcsImlkIjoiYmYxYzY5NWMtN2Y2Mi00N2ZjLWFiMTMtMDFlOTE5ZGQ4MzczIiwicmlkIjoiOTQ5OTYyMTktNWJjYS00YzY1LWE1YTUtNzIyOWEyMzk5N2QyIn0.oaEiClVNqJbyNYKhStkw30KMUUIiuUOhxu9w-qaMYmYp7xCukIjvYOkN5GydwPXX99cCrT5XsBZ_rN7GIVdWCw"


def get_db():
    conn = libsql.connect(
        database=TURSO_DATABASE_URL,
        auth_token=TURSO_AUTH_TOKEN
    )
    return conn


def create_table():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


create_table()


# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "All fields required"}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            (email, hashed_pw)
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "Signup successful"}), 201
    except Exception as e:
        error_message = str(e)
        if "UNIQUE constraint failed" in error_message or "unique" in error_message.lower():
            return jsonify({"error": "User already exists"}), 409
        return jsonify({"error": f"Signup failed: {error_message}"}), 500


# ---------------- LOGIN ----------------
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    conn = get_db()
    cursor = conn.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    )
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.check_password_hash(user[2], password):  # user[2] is the password column
        return jsonify({"message": "Login successful"}), 200

    return jsonify({"error": "Invalid credentials"}), 401


if __name__ == "__main__":
    app.run(debug=True)