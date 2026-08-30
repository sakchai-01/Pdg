import os
import bcrypt
from pymongo import MongoClient
from dotenv import load_dotenv

def hash_password(password: str) -> str:
    if not password:
        return ""
    pw_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pw_bytes, salt).decode('utf-8')

def seed_admin():
    load_dotenv()
    mongo_uri = os.getenv("MONGODB_URI")
    if not mongo_uri:
        print("Error: MONGODB_URI not found in .env")
        return

    try:
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        print("MongoDB connection verified.")
        
        db = client['pdg_db']
        admins = db.admins

        # Check if sakchai already exists
        existing = admins.find_one({"email": "sakchai.te@psru.ac.th"})
        if existing:
            print("Super Admin already exists. Updating password/role...")
            admins.update_one(
                {"email": "sakchai.te@psru.ac.th"},
                {"$set": {
                    "username": "sakchai",
                    "password": hash_password("sakchai2004"),
                    "role": "super_admin"
                }}
            )
        else:
            print("Creating Super Admin sakchai...")
            admins.insert_one({
                "email": "sakchai.te@psru.ac.th",
                "username": "sakchai",
                "password": hash_password("sakchai2004"),
                "role": "super_admin"
            })
        
        print("Admin seeding completed successfully.")
        client.close()
    except Exception as e:
        print(f"Error during seeding: {e}")

if __name__ == "__main__":
    seed_admin()
