import logging

from app.server.auth.auth import auth
from app.server.models.user_models.user import ErrorResponseModel, ResponseModel
from fastapi import APIRouter
from fastapi.params import Depends
from fastapi.security import OAuth2PasswordRequestForm

router = APIRouter()

logger = logging.getLogger(__name__)

#####################################
# POST
#####################################

@router.post('/')
async def get_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await auth.authenticate_user(username=form_data.username, password=form_data.password)
    if user:
        if user.active:
            token = {
                "access_token": auth.create_access_token(
                    json_web_token={
                        'sub': user.username
                    }),
                'token_type': 'bearer'
            }
            return token
        else:
            logger.debug("No Access-Token was created for user {}: User inactive".format(user.username, user.active))
    else:
        logger.debug("User {} not found in database".format(form_data.username))
        return ErrorResponseModel('NoLogin', code=403, message='Invalid Username or Password, or user inactive')


#####################################
# GET
#####################################

@router.get('/', response_description='Test-Route')
async def get_current_user(token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        user = await auth.get_current_user(token=token)
        logger.debug("Test-Route: Got user {}".format(user.username))
        return ResponseModel(data=user, message='Session active, got User')
    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')
