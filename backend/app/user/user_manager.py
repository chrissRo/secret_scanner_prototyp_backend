import logging
import os

from dotenv import load_dotenv
from fastapi.encoders import jsonable_encoder
from pydantic import EmailStr

from app.server.auth.auth import Auth
from app.server.database import user_collection
from app.server.models.user_models.user import UserModel, UserPublicModel


def print_user(user=UserModel):
    print("User in Database: \n{}".format(
        UserPublicModel(username=user['username'], email=user['email'], active=user['active'])
    ))


class UserManager:

    def __init__(self):
        load_dotenv()

        self._auth = Auth()
        self._username = os.getenv("FRONTEND_USERNAME")
        self._password_hash = self._auth.get_password_hash(plain_password=os.getenv("FRONTEND_PASSWORD"))
        self._user_email = os.getenv("FRONTEND_USER_EMAIL")

    async def run(self):
        new_user = await self.create_user()

        if new_user:
            logging.debug('New User created from env-file')
            logging.debug(UserPublicModel(username=new_user['username'], email=new_user['email'], active=new_user['active']))
        else:
            logging.debug('No new User created, use one of the already existing')

    async def user_already_created(self) -> bool:
        user = await user_collection.find_one({'username': self._username})

        if user:
            logging.debug('User already stored in database')
            print_user(user=user)
            return True
        else:
            logging.debug('User not yet stored in database')
            return False

    async def create_user(self) -> UserModel:
        if not await self.user_already_created():
            print("Creating new user ...")
            new_user = await user_collection.insert_one(jsonable_encoder(UserModel(
                username=self._username,
                password=self._password_hash,
                active=True,
                email=EmailStr(self._user_email)
            )))
            if new_user.inserted_id:
                logging.debug('New User created {}'.format(new_user.inserted_id))
                return await user_collection.find_one({'_id': new_user.inserted_id})

