import logging

from fastapi import APIRouter, Depends
from fastapi.params import Body
from app.server.controllers import user_controller
from app.server.auth.auth import auth
from app.server.models.finding_models.finding_model import ErrorResponseModel
from app.server.models.user_models.user import UserPublicModel, UserModel, ResponseModel

logger = logging.getLogger(__name__)

router = APIRouter()

#####################################
# GET
#####################################

@router.get('/{user_id}')
async def get_user(user_id: str, token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        return await user_controller.retrieve_single_user(user_id=user_id)
    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')


@router.get('/')
async def get_all_user(token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        return await user_controller.retrieve_all_user()
    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')


#####################################
# POST
#####################################

# This route is currently unused in the frontend
@router.post('/signup')
async def create_user(user: UserModel = Body(...), token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        user_check = await user_controller.retrieve_single_user(username=user.username)
        if not user_check:
            user_status = await user_controller.insert_single_user(user=user)
            new_user = await user_controller.retrieve_single_user(user_id=user_status.inserted_id)
            return ResponseModel(data=UserPublicModel(**new_user), message='User created successfully')
        else:
            return ResponseModel(data=UserPublicModel(**user_check), message='User already exists')
    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')




