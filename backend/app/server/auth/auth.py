import logging
import os
from datetime import datetime, timedelta

import jwt as jwt
from dotenv import load_dotenv
from fastapi import HTTPException
from fastapi.security import OAuth2PasswordBearer
from jwt import ExpiredSignatureError
from passlib.context import CryptContext

from app.server.controllers import user_controller
from app.server.models.user_models.user import UserPublicModel
from config.config import JWTConfig

logger = logging.getLogger(__name__)

class Auth:
    @property
    def oauth2scheme(self):
        return self._oauth2scheme

    @oauth2scheme.setter
    def oauth2scheme(self, value):
        self._oauth2scheme = value

    def __init__(self):
        load_dotenv()
        self._pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self._oauth2scheme = OAuth2PasswordBearer(tokenUrl='token')
        self.jwt_secret_key = os.getenv('JWT_SECRET_KEY')
        self.jwt_signing_algorithm = JWTConfig.ALGORITHM
        self.jwt_expiration_time_mins = JWTConfig.ACCESS_TOKEN_EXPIRE_MINUTES

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        ret_val = self._pwd_context.verify(plain_password, hashed_password)
        logger.debug("Verifying password: {}".format(ret_val))
        return ret_val

    def get_password_hash(self, plain_password) -> str:
        return self._pwd_context.hash(plain_password)

    async def authenticate_user(self, username: str, password: str) -> UserPublicModel:
        user = await user_controller.retrieve_single_user_private(username=username)
        if user:
            logger.debug("Found user {} in DB".format(user))
            if self.verify_password(plain_password=password, hashed_password=user['password']):
                return UserPublicModel(username=user['username'], email=user['email'], active=user['active'])
            else:
                logger.debug("Password verification failed. User {} not authenticated".format(user))
        else:
            logger.debug("User {} invalid. Not found in DB".format(user))

    def create_access_token(self, json_web_token: dict) -> dict:
        json_web_token.update({
                "exp": datetime.utcnow() + timedelta(minutes=self.jwt_expiration_time_mins),
                'iss': JWTConfig.ISSUER
            })
        return jwt.encode(
            payload=json_web_token,
            key=self.jwt_secret_key,
            algorithm=self.jwt_signing_algorithm
        )

    async def get_current_user(self, token: jwt) -> UserPublicModel:
        payload = jwt.decode(
            jwt=token,
            key=self.jwt_secret_key,
            algorithms=[self.jwt_signing_algorithm]
        )
        username = payload.get("sub")
        if username:
            logger.debug("User {} from JWT".format(username))
            return await user_controller.retrieve_single_user(username=username)
        else:
            logger.debug("Could not extract user from JWT")

    async def is_authenticated(self, token: jwt) -> bool:
        try:
            current_user = await self.get_current_user(token=token)
            if current_user and current_user['active']:
                logger.debug("User {} authenticated".format(current_user))
                return True
            logger.debug("User not authenticated")
            return False
        except ExpiredSignatureError:
            logger.debug("Provided JWT is expired")
            raise HTTPException(status_code=403, detail='token expired')


auth = Auth()
