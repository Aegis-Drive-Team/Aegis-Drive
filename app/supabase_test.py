import os
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv() # Load environment variables from a .env file if used

SUPABASE_URL = os.getenv("SUPABASE_API_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
# Select all columns from the 'your_table_name' table
response = (supabase.table('ip_reports').select('*').execute())

# Access the data

print(response)