import os
import bcrypt
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()
mongo_uri = os.getenv("MONGODB_URI")
client = MongoClient(mongo_uri)
db = client['pdg_db']

admin = db.admins.find_one({"email": "sakchai.te@psru.ac.th"})
print("Admin in DB:", admin)

if admin and "password" in admin:
    test_password = "sakchai2004"
    pw_bytes = test_password.encode('utf-8')[:72]
    hash_bytes = admin['password'].encode('utf-8')
    match = bcrypt.checkpw(pw_bytes, hash_bytes)
    print(f"Password 'sakchai2004' matches: {match}")
