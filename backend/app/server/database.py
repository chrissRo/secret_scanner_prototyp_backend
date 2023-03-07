import os

import motor.motor_asyncio
from dotenv import load_dotenv
from pymongo.errors import ServerSelectionTimeoutError

load_dotenv()

try:
    mongo_details = f"mongodb://{os.getenv('MONGODB_USER')}:{os.getenv('MONGODB_PASSWORD')}@localhost:27017" \
                    f"/?authMechanism=DEFAULT "
except ServerSelectionTimeoutError as e:
    print("Hostname: mongodb_container not found")
    print("Will try again with localhost")
    mongo_details = f"mongodb://{os.getenv('MONGODB_USER')}:{os.getenv('MONGODB_PASSWORD')}@mongodb_container:27017" \
                    f"/?authMechanism=DEFAULT "

db_client = motor.motor_asyncio.AsyncIOMotorClient(mongo_details)

findings_collection = db_client.findings.get_collection('findings_collection')
user_collection = db_client.users.get_collection('user_collection')
