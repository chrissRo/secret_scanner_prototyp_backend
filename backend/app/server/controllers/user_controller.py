import logging

from fastapi.encoders import jsonable_encoder
from app.server.database import user_collection
from app.server.models.user_models.user import UserModel, UserPublicModel

logger = logging.getLogger(__name__)

#####################################
# GET
#####################################

async def retrieve_single_user(user_id: str = '', username: str = '') -> UserPublicModel:
    if user_id:
        logger.debug("Found user with user_id {} in database".format(user_id))
        return await user_collection.find_one({'_id': user_id})
    if username:
        logger.debug("Found user {} in database".format(username, user_id))
        return await user_collection.find_one({'username': username})
    else:
        logger.debug("Did not find user for user_id {} in database".format(user_id))


async def retrieve_single_user_private(username: str) -> UserModel:
    return await user_collection.find_one({'username': username})


async def retrieve_all_user() -> list:
    users = []
    async for user in user_collection.find():
        users.append(user)
    logger.debug("Found {} users in database".format(len(users)))
    return users


#####################################
# POST
#####################################

async def insert_single_user(user: UserModel):
    from app.server.auth.auth import auth
    user.password = auth.get_password_hash(plain_password=user.password)
    return await user_collection.insert_one(jsonable_encoder(user))
