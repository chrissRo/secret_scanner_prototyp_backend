import os

import motor.motor_asyncio
from dotenv import load_dotenv

load_dotenv()

mongo_details = f"mongodb://{os.getenv('MONGODB_USER')}:{os.getenv('MONGODB_PASSWORD')}@mongodb_container:27017" \
                f"/?authMechanism=DEFAULT "

db_client = motor.motor_asyncio.AsyncIOMotorClient(mongo_details)

findings_collection = db_client.findings.get_collection('findings_collection')
user_collection = db_client.users.get_collection('user_collection')
