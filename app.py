"""Cybersecurity Incident Reporting System."""

from functools import wraps
import hmac
import os
import re
import secrets

import mysql.connector
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from database import Error, get_db_connection, init_db


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

INCIDENT_TYPES = [
    "Phishing",
    "Malware",
    "Ransomware",
    "Unauthorized Access",
    "Data Breach",
    "DDoS",
    "Password Attack",
    "Other",
]
SEVERITIES = ["Low", "Medium", "High", "Critical"]
STATUSES = ["Open", "Investigating", "Resolved"]
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def db_fetch_all(query, params=()):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(query, params)
        return cursor.fetchall()
    finally:
        cursor.close()
        connection.close()


def db_fetch_one(query, params=()):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(query, params)
        return cursor.fetchone()
    finally:
        cursor.close()
        connection.close()


def db_execute(query, params=()):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(query, params)
        connection.commit()
        return cursor.rowcount, cursor.lastrowid
    finally:
        cursor.close()
        connection.close()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        expected = session.get("csrf_token", "")
        submitted = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected, submitted):
            flash("Your form session expired. Please try again.", "warning")
            return redirect(request.referrer or url_for("index"))
    return None


@app.context_processor
def inject_template_values():
    return {
        "csrf_token": csrf_token,
        "current_username": session.get("username"),
        "incident_types": INCIDENT_TYPES,
        "severities": SEVERITIES,
        "statuses": STATUSES,
    }


def get_incident(incident_id):
    return db_fetch_one(
        """SELECT i.id, i.title, i.incident_type, i.description, i.severity,
                  i.affected_system, i.status, i.reported_by, i.reported_date,
                  u.username AS reporter
           FROM incidents AS i
           JOIN users AS u ON u.id = i.reported_by
           WHERE i.id = %s""",
        (incident_id,),
    )


def validate_incident_form(form):
    data = {
        "title": form.get("title", "").strip(),
        "incident_type": form.get("incident_type", "").strip(),
        "description": form.get("description", "").strip(),
        "severity": form.get("severity", "").strip(),
        "affected_system": form.get("affected_system", "").strip(),
        "status": form.get("status", "").strip(),
    }
    errors = []
    if not all(data.values()):
        errors.append("Complete every field before saving the incident.")
    if len(data["title"]) > 150:
        errors.append("Incident title must be 150 characters or fewer.")
    if len(data["affected_system"]) > 150:
        errors.append("Affected system must be 150 characters or fewer.")
    if data["incident_type"] not in INCIDENT_TYPES:
        errors.append("Choose a valid incident type.")
    if data["severity"] not in SEVERITIES:
        errors.append("Choose a valid severity.")
    if data["status"] not in STATUSES:
        errors.append("Choose a valid status.")
    return data, errors


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        errors = []
        if not username or not email or not password or not confirm_password:
            errors.append("Complete every field to create your account.")
        if username and (len(username) < 3 or len(username) > 30):
            errors.append("Username must be between 3 and 30 characters.")
        if email and (len(email) > 120 or not EMAIL_PATTERN.fullmatch(email)):
            errors.append("Enter a valid email address.")
        if password and len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        if password and len(password) > 128:
            errors.append("Password must be 128 characters or fewer.")
        if password != confirm_password:
            errors.append("Password and confirmation do not match.")
        if errors:
            for message in errors:
                flash(message, "danger")
            return render_template("register.html", username=username, email=email)

        existing_username = db_fetch_one("SELECT id FROM users WHERE username = %s", (username,))
        existing_email = db_fetch_one("SELECT id FROM users WHERE email = %s", (email,))
        if existing_username:
            flash("That username is already registered.", "danger")
            return render_template("register.html", username=username, email=email)
        if existing_email:
            flash("That email address is already registered.", "danger")
            return render_template("register.html", username=username, email=email)

        try:
            db_execute(
                "INSERT INTO users (username, email, `password`) VALUES (%s, %s, %s)",
                (username, email, generate_password_hash(password)),
            )
        except mysql.connector.IntegrityError:
            flash("That username or email is already registered.", "danger")
            return render_template("register.html", username=username, email=email)
        flash("Account created. You can now log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")
        if not identity or not password:
            flash("Enter your username or email and password.", "danger")
            return render_template("login.html", identity=identity)
        user = db_fetch_one(
            "SELECT id, username, email, `password` FROM users WHERE username = %s OR email = %s",
            (identity, identity.lower()),
        )
        if not user or not check_password_hash(user["password"], password):
            flash("Invalid username/email or password.", "danger")
            return render_template("login.html", identity=identity)
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        csrf_token()
        flash("Welcome back, " + user["username"] + ".", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    metrics = db_fetch_one(
        """SELECT COUNT(*) AS total,
                  COALESCE(SUM(status = 'Open'), 0) AS open_count,
                  COALESCE(SUM(status = 'Resolved'), 0) AS resolved_count,
                  COALESCE(SUM(severity = 'Critical'), 0) AS critical_count,
                  COALESCE(SUM(severity = 'High'), 0) AS high_count
           FROM incidents"""
    )
    recent_incidents = db_fetch_all(
        """SELECT i.id, i.title, i.incident_type, i.severity, i.status,
                  i.reported_date, u.username AS reporter
           FROM incidents AS i JOIN users AS u ON u.id = i.reported_by
           ORDER BY i.reported_date DESC, i.id DESC LIMIT 8"""
    )
    return render_template("dashboard.html", metrics=metrics, incidents=recent_incidents)


@app.route("/incidents")
@login_required
def incidents():
    search = request.args.get("q", "").strip()
    if search:
        term = "%" + search + "%"
        rows = db_fetch_all(
            """SELECT i.id, i.title, i.incident_type, i.severity, i.affected_system,
                      i.status, i.reported_by, i.reported_date, u.username AS reporter
               FROM incidents AS i JOIN users AS u ON u.id = i.reported_by
               WHERE i.title LIKE %s OR i.incident_type LIKE %s OR i.status LIKE %s
               ORDER BY i.reported_date DESC, i.id DESC""",
            (term, term, term),
        )
    else:
        rows = db_fetch_all(
            """SELECT i.id, i.title, i.incident_type, i.severity, i.affected_system,
                      i.status, i.reported_by, i.reported_date, u.username AS reporter
               FROM incidents AS i JOIN users AS u ON u.id = i.reported_by
               ORDER BY i.reported_date DESC, i.id DESC"""
        )
    return render_template("incidents.html", incidents=rows, search=search)


@app.route("/incident/add", methods=["GET", "POST"])
@login_required
def add_incident():
    if request.method == "POST":
        data, errors = validate_incident_form(request.form)
        if errors:
            for message in errors:
                flash(message, "danger")
            return render_template("add_incident.html", incident=data)
        db_execute(
            """INSERT INTO incidents
               (title, incident_type, description, severity, affected_system, status, reported_by)
               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (
                data["title"], data["incident_type"], data["description"], data["severity"],
                data["affected_system"], data["status"], session["user_id"],
            ),
        )
        flash("Incident report submitted successfully.", "success")
        return redirect(url_for("incidents"))
    return render_template("add_incident.html", incident={})


@app.route("/incident/view/<int:incident_id>")
@login_required
def incident_details(incident_id):
    incident = get_incident(incident_id)
    if not incident:
        abort(404)
    return render_template("incident_details.html", incident=incident)


@app.route("/incident/edit/<int:incident_id>", methods=["GET", "POST"])
@login_required
def edit_incident(incident_id):
    incident = get_incident(incident_id)
    if not incident:
        abort(404)
    if incident["reported_by"] != session["user_id"]:
        abort(403)
    if request.method == "POST":
        data, errors = validate_incident_form(request.form)
        if errors:
            for message in errors:
                flash(message, "danger")
            return render_template("edit_incident.html", incident={**incident, **data})
        db_execute(
            """UPDATE incidents SET title = %s, incident_type = %s, description = %s,
                      severity = %s, affected_system = %s, status = %s
               WHERE id = %s AND reported_by = %s""",
            (
                data["title"], data["incident_type"], data["description"], data["severity"],
                data["affected_system"], data["status"], incident_id, session["user_id"],
            ),
        )
        flash("Incident updated successfully.", "success")
        return redirect(url_for("incidents"))
    return render_template("edit_incident.html", incident=incident)


@app.post("/incident/delete/<int:incident_id>")
@login_required
def delete_incident(incident_id):
    incident = get_incident(incident_id)
    if not incident:
        abort(404)
    if incident["reported_by"] != session["user_id"]:
        abort(403)
    db_execute(
        "DELETE FROM incidents WHERE id = %s AND reported_by = %s",
        (incident_id, session["user_id"]),
    )
    flash("Incident deleted successfully.", "success")
    return redirect(url_for("incidents"))


@app.errorhandler(403)
def forbidden(_error):
    return render_template(
        "error.html", code=403, title="Access denied", message="You can only edit or delete incidents you reported."
    ), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template(
        "error.html", code=404, title="Incident not found", message="The requested page or incident could not be found."
    ), 404


@app.errorhandler(Error)
def database_error(error):
    app.logger.error("Database operation failed: %s", error)
    return render_template(
        "error.html", code=503, title="Database unavailable",
        message="Could not reach MySQL. Start MySQL in XAMPP and check the database settings in database.py.",
    ), 503


if __name__ == "__main__":
    try:
        init_db()
        print("Database tables are ready.")
    except Error as error:
        app.logger.warning("Database initialization skipped: %s", error)
        print("Database is not ready. Start XAMPP MySQL and create cyber_incident_db before using the app.")
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG") == "1")
