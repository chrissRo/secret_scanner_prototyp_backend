import logging
import os

import motor.motor_asyncio
from dotenv import load_dotenv
from pymongo.errors import ServerSelectionTimeoutError

logger = logging.getLogger(__name__)

load_dotenv()

try:
    # mongo_details = f"mongodb://{os.getenv('MONGODB_USER')}:{os.getenv('MONGODB_PASSWORD')}@localhost:27017" \
    #                f"/?authMechanism=DEFAULT "

    mongo_details = f"mongodb://{os.getenv('MONGODB_USER')}:{os.getenv('MONGODB_PASSWORD')}@mongodb_container:27017" \
                    f"/?authMechanism=DEFAULT "

    if mongo_details:
        logger.debug("Connecting to database successful")
    else:
        logger.debug("Error connecting to database")
except ServerSelectionTimeoutError as e:
    logger.debug("Hostname: mongodb_container not found")
    logger.debug("Will try again with localhost")
    mongo_details = f"mongodb://{os.getenv('MONGODB_USER')}:{os.getenv('MONGODB_PASSWORD')}@mongodb_container:27017" \
                    f"/?authMechanism=DEFAULT "


db_client = motor.motor_asyncio.AsyncIOMotorClient(mongo_details)
if db_client:
    logger.debug("Got db_client")
else:
    logger.debug("Error getting db_client")

findings_collection = db_client.findings.get_collection('findings_collection')
if findings_collection is not None:
    logger.debug("Got collection findings_collection")
else:
    logger.debug("Error getting collection findings_collection")

user_collection = db_client.users.get_collection('user_collection')
if user_collection is not None:
    logger.debug("Got collection user_collection")
else:
    logger.debug("Error getting collection user_collection")
