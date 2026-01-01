import psycopg
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

DB_URL = os.getenv("DATABASE_URL")

# Connect to Postgres using psycopg3
def get_connection():
    return psycopg.connect(DB_URL)


# Create a new user (general or admin)
def create_user(username, password, role="general"):
    """Create a user using PostgreSQL crypt() hashing."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (%s, crypt(%s, gen_salt('bf')), %s)
                RETURNING id;
                """,
                (username, password, role)
            )

            new_id = cur.fetchone()[0]

        conn.commit()

    return new_id



# Verify login credentials
def verify_user(username, password):
    """Return user row if valid, else None."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, username, password, role
                FROM users
                WHERE username = %s;
                """,
                (username,)
            )
            row = cur.fetchone()

    if row is None:
        return None

    stored_hash = row[2]

    if not check_password_hash(stored_hash, password):
        return None

    # Return a dict instead of tuple
    return {
        "id": row[0],
        "username": row[1],
        "role": row[3]
    }


# Get user role
def get_user_role(username):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT role FROM users WHERE username = %s;",
                (username,)
            )
            row = cur.fetchone()

    return row[0] if row else None

