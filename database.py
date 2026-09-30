"""MySQL connection and schema setup for the incident reporting app."""

import os

import mysql.connector
from mysql.connector import Error


DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "cyber_incident_db")


def get_db_connection():
    """Open a connection using environment variables or XAMPP defaults."""
    return mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        use_unicode=True,
    )


def init_db():
    """Create the required tables when the database already exists."""
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(30) NOT NULL UNIQUE,
                email VARCHAR(120) NOT NULL UNIQUE,
                `password` VARCHAR(255) NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""
        )
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS incidents (
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
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""
        )
        connection.commit()
    finally:
        cursor.close()
        connection.close()


__all__ = ["DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME", "Error", "get_db_connection", "init_db"]
