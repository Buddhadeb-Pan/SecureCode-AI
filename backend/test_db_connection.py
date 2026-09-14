"""
Verification script for SecureCode AI MySQL database connection.
Tests connection health, database name, and accessibility of the users table.
Does NOT expose or log plaintext credentials.
"""

import sys
import os
import re
from sqlalchemy import text, inspect

# Ensure current directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.database import get_engine, get_db, Base
from database.models import User


def verify_mysql_connection():
    print("==================================================")
    print("SECURECODE AI - MYSQL CONNECTION VERIFICATION")
    print("==================================================")

    # 1. Retrieve and mask DATABASE_URL for safe logging
    raw_url = os.getenv("DATABASE_URL")
    if not raw_url:
        print("[FAIL] DATABASE_URL is not set in environment or .env file.")
        return False

    masked_url = re.sub(r":([^@]+)@", ":****@", raw_url)
    print(f"Configured URL: {masked_url}")

    try:
        engine = get_engine()

        # 2. Test live connection
        print("\n[Step 1] Connecting to MySQL server...")
        with engine.connect() as conn:
            row = conn.execute(text("SELECT DATABASE(), VERSION();")).fetchone()
            current_db = row[0] if row else None
            mysql_version = row[1] if row else "Unknown"

            print(f"  -> Connection: SUCCESSFUL")
            print(f"  -> MySQL Version: {mysql_version}")
            print(f"  -> Connected Database: {current_db}")

            # 3. Verify database name
            if current_db != "securecode_ai":
                print(f"[FAIL] Expected database 'securecode_ai', got '{current_db}'")
                return False
            print("  -> Database Name Verification: PASSED (securecode_ai)")

            # 4. Check / Ensure users table
            print("\n[Step 2] Checking 'users' table accessibility...")
            # Ensure table exists according to models schema
            Base.metadata.create_all(bind=engine)

            inspector = inspect(engine)
            tables = inspector.get_table_names()
            if "users" not in tables:
                print("  [FAIL] 'users' table not found in database.")
                return False

            columns = [col["name"] for col in inspector.get_columns("users")]
            print(f"  -> 'users' table found: YES")
            print(f"  -> Table columns: {', '.join(columns)}")

        # 5. Verify Session / ORM query on User model
        print("\n[Step 3] Testing ORM Session query on User model...")
        db = next(get_db())
        try:
            user_count = db.query(User).count()
            print(f"  -> Query execution: SUCCESSFUL")
            print(f"  -> Current user records count: {user_count}")
        finally:
            db.close()

        print("\n==================================================")
        print("ALL DATABASE CHECKS PASSED SUCCESSFULLY!")
        print("==================================================")
        return True

    except Exception as err:
        print(f"\n[FAIL] Database verification failed: {type(err).__name__}: {err}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = verify_mysql_connection()
    sys.exit(0 if success else 1)
