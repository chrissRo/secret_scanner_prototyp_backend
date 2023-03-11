import logging
import os
from fastapi import APIRouter, Depends, HTTPException
from app.server.auth.auth import auth
from app.server.controllers.scan_manager_controller import start_file_import
from app.server.models.finding_models.finding_model import ErrorResponseModel, UploadNewFindingModelForm, \
    SimpleResponseModel
from config.config import GitleaksConfig

logger = logging.getLogger(__name__)

router = APIRouter()

#####################################
# POST
#####################################

@router.post('/start_import/{file}', response_description='Start import of finding into DB')
async def get_import_start(file: str, file_meta_data: UploadNewFindingModelForm = Depends(), token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        if file in os.listdir(GitleaksConfig.FS_RAW_INPUT_PATH):
            logger.debug('File {} in RAW_INPUT_PATH {}'.format(file, GitleaksConfig.FS_RAW_INPUT_PATH))
            results = await start_file_import(file=file, file_meta_data=file_meta_data)
            if results:
                logger.debug("{} entries in DB created successfully".format(len(results)))
                return SimpleResponseModel(data=results, message='DB entries created successfully', code=201)
            else:
                logger.debug("Failed to process data of file {}".format(file))
                raise HTTPException(status_code=422, detail='Failed to process data')
        else:
            logger.debug('The provided file {} is not available'.format(file))
            raise HTTPException(status_code=404, detail='The filename you have provided is not available on this server')

    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')
