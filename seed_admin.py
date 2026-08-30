import os
import asyncio
import bcrypt
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import sys

def hash_password(password: str) -> str:
    if not password:
        return ""
    pw_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pw_bytes, salt).decode('utf-8')

async def seed_admin():
    load_dotenv()
    mongo_uri = os.getenv("MONGODB_URI")
    if not mongo_uri:
        print("Error: MONGODB_URI not found in .env")
        return

    client = AsyncIOMotorClient(mongo_uri)
    db = client.get_default_database()
    admins = db.admins

    # Check if sakchai already exists
    existing = await admins.find_one({"email": "sakchai.te@psru.ac.th"})
    if existing:
        print("Super Admin already exists. Updating password/role...")
        await admins.update_one(
            {"email": "sakchai.te@psru.ac.th"},
            {"$set": {
                "username": "sakchai",
                "password": hash_password("sakchai2004"),
                "role": "super_admin"
            }}
        )
    else:
        print("Creating Super Admin sakchai...")
        await admins.insert_one({
            "email": "sakchai.te@psru.ac.th",
            "username": "sakchai",
            "password": hash_password("sakchai2004"),
            "role": "super_admin"
        })
    
    print("Admin seeding completed.")
    client.close()

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(seed_admin())
