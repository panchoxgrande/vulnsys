import psycopg2
import os
from urllib.parse import urlparse

def get_db_connection():
    """Establishes and returns a connection to the PostgreSQL database."""
    try:
        database_url = os.getenv("DATABASE_URL")
        if database_url:
            result = urlparse(database_url)
            db_config = {
                "dbname": result.path[1:],
                "user": result.username,
                "password": result.password,
                "host": result.hostname,
                "port": result.port
            }
        else:
            db_config = {
                "dbname": os.getenv("DB_NAME", "vulnerability_manager"),
                "user": os.getenv("DB_USER", "postgres"),
                "password": os.getenv("DB_PASSWORD", "Chino01*"),
                "host": os.getenv("DB_HOST", "localhost"),
                "port": os.getenv("DB_PORT", "5432"),
                "client_encoding": "utf8"
            }
            if db_config["password"] == "your_password_here":
                print("[DB WARN] Usando la contraseña por defecto de 'database.py'. Asegúrate de cambiarla o usar la variable de entorno DB_PASSWORD.")
        
        conn = psycopg2.connect(**db_config)
        return conn
    except psycopg2.OperationalError as e:
        print(f"[DB ERROR] Could not connect to the database: {e}")
        print("Please ensure PostgreSQL is running and that the configuration in database.py is correct.")
        return None
