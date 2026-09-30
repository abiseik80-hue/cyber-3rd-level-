# Cybersecurity Incident Reporting System

A beginner-friendly Flask application for registering users and reporting, tracking, editing, and deleting cybersecurity incidents. It uses Flask sessions, Werkzeug password hashing, parameterized MySQL queries, and a MySQL database served locally by XAMPP.

## Requirements

- Windows 10/11 (the commands below use PowerShell)
- Python 3.10 or newer
- XAMPP with MySQL/MariaDB; Apache is useful for opening phpMyAdmin
- A web browser

The interface loads Bootstrap 5 and Bootstrap Icons from jsDelivr, so an internet connection is needed for those visual assets. Flask and MySQL themselves run locally.

## 1. Install Python and XAMPP

Install Python from [python.org](https://www.python.org/downloads/) and select **Add Python to PATH** during setup. Install XAMPP from [apachefriends.org](https://www.apachefriends.org/).

## 2. Start XAMPP

Open the XAMPP Control Panel and start **MySQL**. Start **Apache** too if you want to use phpMyAdmin. Click **Admin** beside MySQL, or visit `http://localhost/phpmyadmin`.

## 3. Create the database

In phpMyAdmin, select **New**, enter `cyber_incident_db`, and create it. You can alternatively select the **SQL** tab and run:

```sql
CREATE DATABASE cyber_incident_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
```

The application creates the `users` and `incidents` tables automatically the first time `python app.py` runs. If you prefer to create them yourself in phpMyAdmin, select the new database, open the **SQL** tab, and run the following statements. The app will leave existing tables in place.

```sql
USE cyber_incident_db;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(30) NOT NULL UNIQUE,
  email VARCHAR(120) NOT NULL UNIQUE,
  `password` VARCHAR(255) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS incidents (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(150) NOT NULL,
  incident_type VARCHAR(50) NOT NULL,
  description TEXT NOT NULL,
  severity ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL,
  affected_system VARCHAR(150) NOT NULL,
  status ENUM('Open', 'Investigating', 'Resolved') NOT NULL DEFAULT 'Open',
  reported_by INT NOT NULL,
  reported_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_incidents_reporter FOREIGN KEY (reported_by)
    REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

## 4. Configure MySQL

The defaults in `database.py` match a standard XAMPP installation: host `localhost`, port `3306`, user `root`, no password, and database `cyber_incident_db`. If your XAMPP MySQL root account has a password or uses another port, set environment variables in the same PowerShell window used to start Flask:

```powershell
$env:DB_HOST = "localhost"
$env:DB_PORT = "3306"
$env:DB_USER = "root"
$env:DB_PASSWORD = "your-local-mysql-password"
$env:DB_NAME = "cyber_incident_db"
```

Set a private session signing key for this local run as well:

```powershell
$env:FLASK_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
```

The built-in fallback key is intended only for a local demonstration. Do not use it for a public deployment.

## 5. Install Python packages

Open PowerShell in the project folder:

```powershell
cd "$HOME\Desktop\3\Cybersecurity_Incident_System"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, you can skip activation and use the virtual environment directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## 6. Run the app

Make sure XAMPP MySQL is running, then run:

```powershell
python app.py
```

The terminal should report that the database tables are ready. Open **http://127.0.0.1:5000** in your browser. If MySQL is unavailable, the Flask server still starts and displays a friendly database error page; start MySQL and check the configuration before retrying.

To enable Flask debug mode for local development only:

```powershell
$env:FLASK_DEBUG = "1"
python app.py
```

## 7. Use the application

1. Choose **Create an account** and register a username, email, and password. Passwords must be at least 8 characters; the stored value is a Werkzeug password hash, not the original password.
2. Log in with either your username or email and your password.
3. Choose **Report Incident**, complete each required field, and submit the report.
4. Choose **View Incidents** to browse all reports or search by title, incident type, or status.
5. Open an incident with **View** to inspect all report details.
6. Use **Edit** to update an incident you reported. Only its reporter can edit or delete it.
7. Use **Delete** and confirm the browser prompt to remove your report.
8. Choose **Logout** to end the Flask session.

## Database configuration and security notes

- `users.id` is the primary key. `incidents.reported_by` references `users.id`; deleting a user cascades to their reports.
- Usernames and email addresses are unique. SQL values are passed as parameters rather than concatenated into queries.
- Forms validate required values and include a session-based CSRF token. Data-changing routes use POST requests.
- Authenticated users can see workspace reports, but only the original reporter can edit or delete each report.
- The Flask development server is for localhost demonstrations. Do not expose it publicly or use the development fallback key in production.
