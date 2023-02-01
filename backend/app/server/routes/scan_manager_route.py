from fastapi import APIRouter, Depends

from app.server.auth.auth import auth
from app.server.controllers.scan_manager_controller import start_file_import
from app.server.models.finding_models.finding_model import ErrorResponseModel, UploadNewFindingModelForm, ResponseModel

router = APIRouter()

#####################################
# POST
#####################################

@router.post('/start_import/{file}', response_description='Start import of finding into DB')
async def get_import_start(file: str, file_meta_data: UploadNewFindingModelForm = Depends(), token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        results = await start_file_import(file=file, file_meta_data=file_meta_data)
        return ResponseModel(data=results, message='DB Entries created successfully', code=201)
    else:
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')