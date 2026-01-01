from werkzeug.security import generate_password_hash, check_password_hash
from db_post import get_supabase, get_connection

from supabase import create_client
import os
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def get_user_conn():
    """ grabs supabase db, returning that conn """
    conn = get_connection()
    conn = conn.table("users")
    return conn


def create_user(username, password, is_admin=False):
    try:
        password_hash = generate_password_hash(password)
        user = supabase.table("users").insert({
            "username": username,
            "password_hash": password_hash,
            #"is_admin": is_admin
        }).execute()
        if user.data:
            return True
        else:
            print("Error creating account:", user.data)
            return False
    except Exception as e:
        print("Error creating account:", e)
        return False


from werkzeug.security import check_password_hash

def verify_user(username, password):
    try:
        response = supabase.table("users").select("*").eq("username", username).execute()
        user_data = response.data

        if not user_data:
            return None

        user = user_data[0]

        if check_password_hash(user["password_hash"], password):
            return user
        else:
            return None
    except Exception as e:
        print("Error verifying user:", e)
        return None
