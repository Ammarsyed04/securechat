#!/usr/bin/env python3
"""
Initialize the database schema and create a test user.
Run this script once before starting the server.
"""

import os
from dotenv import load_dotenv
from app.storage.db import init_schema, create_user

# Load environment variables from .env file if it exists
load_dotenv()

def main():
    print("Initializing database schema...")
    init_schema()
    print("✓ Database schema created")
    
    print("\nCreating test user (alice/alice123)...")
    if create_user("alice@example.com", "alice", "alice123"):
        print("✓ User 'alice' created successfully")
    else:
        print("⚠ User 'alice' may already exist (this is OK)")
    
    print("\nDatabase initialization complete!")
    print("You can now start the server with: python app/server.py")

if __name__ == "__main__":
    main()

