from app.server.auth.auth import auth
from app.server.models.user_models.user import ErrorResponseModel, ResponseModel
from fastapi import APIRouter
from fastapi.params import Depends
from fastapi.security import OAuth2PasswordRequestForm

router = APIRouter()


#####################################
# POST
#####################################

@router.post('/')
async def get_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await auth.authenticate_user(username=form_data.username, password=form_data.password)
    if user and user.active:
        return {
            "access_token": auth.create_access_token(
                json_web_token={
                    'sub': user.username
                }),
            'token_type': 'bearer'
        }
    else:
        # Todo Error handling
        print('Invalid username or password')
        return ErrorResponseModel('NoLogin', code=403, message='Invalid Username or Password, or user inactive')


#####################################
# GET
#####################################

@router.get('/', response_description='Test-Route')
async def get_current_user(token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        user = await auth.get_current_user(token=token)
        return ResponseModel(data=user, message='Session active, got User')
    else:
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')
