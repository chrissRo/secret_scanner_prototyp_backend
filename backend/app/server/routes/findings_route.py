import logging
from typing import List

from fastapi import APIRouter, Depends, UploadFile, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.params import Body

from app.server.auth.auth import auth
from app.server.controllers.findings_controller import retrieve_all_findings, set_false_positive, \
    retrieve_single_finding, retrieve_overview_data_count, retrieve_overview_data, \
    retrieve_all_findings_for_repository, retrieve_overview_data_count_for_repository, set_favourite, \
    upload_new_findings, upload_new_finding_file, retrieve_all_favourite_findings, retrieve_all_true_positives
from app.server.models.finding_models.finding_model import ResponseModel, ErrorResponseModel, \
    SimpleResponseModel, UpdateFindingModelFalsePositive, UpdateResponseModel, UpdateFindingModelFavourite, \
    UploadNewFindingModelRaw, UploadNewFindingModelForm

logger = logging.getLogger(__name__)

router = APIRouter()


#####################################
# GET
#####################################

@router.get('/count', response_description='Get counted overview-data for all findings')
async def get_finding_overview_count(token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        data_count = await retrieve_overview_data_count()
        if data_count:
            logger.debug('Data count over all repositories calculated successfully')
            return SimpleResponseModel(data_count, 'Data count retrieved successfully')
        else:
            logger.debug('Could not calculate data count over all repositories')
            ErrorResponseModel('An error occurred.', 500, 'Could not calculate data count')
    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')

@router.get('/repository/{repository_id}/count', response_description='Get counted overview-data for given repository')
async def get_finding_overview_count(repository_id: str, token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        data_count = await retrieve_overview_data_count_for_repository(repository_id)
        if data_count:
            logger.debug('Data count for repository_id {} retrieved successfully'.format(repository_id))
            return SimpleResponseModel(data_count, 'Data count for repository "{}" retrieved successfully'.format(repository_id))
        else:
            logger.debug('Could not count data for repository_id {}'.format(repository_id))
            ErrorResponseModel('An error occurred.', 500, 'Could not calculate data count for {}'.format(repository_id))
    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')

@router.get('/overview', response_description='Get overview-data to all findings')
async def get_finding_overview(token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        data = await retrieve_overview_data()
        if data:
            logger.debug("Data overview retrieved successfully")
            return SimpleResponseModel(jsonable_encoder(data), "Data retrieved successfully")
        else:
            logger.debug("Could not retrieve data overview")
            ErrorResponseModel('An error occurred.', 500, 'Could not retrieve data overview')
    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')

@router.get('/favourites', response_description='Get all favourite findings')
async def get_all_favourite_findings(token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        findings = await retrieve_all_favourite_findings()
        if findings:
            logger.debug("All favourite findings retrieved successfully")
            return SimpleResponseModel(findings, 'All favourite findings retrieved successfully')
        else:
            logger.debug("Could not retrieve all favourite findings")
            return ErrorResponseModel('An error occurred.', 500, 'Could not retrieve all favourite findings')
    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')

@router.get('/true_positives', response_description='Get all true-positive findings')
async def get_all_favourite_findings(token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        findings = await retrieve_all_true_positives()
        if findings:
            logger.debug("All true-positive findings retrieved successfully")
            return SimpleResponseModel(findings, 'All true-positive findings retrieved successfully')
        else:
            logger.debug("Could not retrieve all true-positive findings")
            return ErrorResponseModel('An error occurred.', 500, 'Could not retrieve all true-positive findings')
    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')


@router.get('/', response_description='Get all findings')
async def get_all_findings(token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        findings = await retrieve_all_findings()
        if findings:
            logger.debug("All findings retrieved successfully")
            return ResponseModel(findings, 'All findings retrieved successfully')
        else:
            logger.debug("Could not retrieve findings")
            return ErrorResponseModel('An error occurred.', 500, 'Could not retrieve findings')
    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')


@router.get('/{finding_id}', response_description='Get single finding')
async def get_single_finding(finding_id: str, token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        finding = await retrieve_single_finding(finding_id=finding_id)
        if finding:
            logger.debug('Finding {} retrieved successfully.'.format(finding_id))
            return ResponseModel(finding, 'Finding "{}" retrieved successfully.'.format(finding_id))
        else:
            logger.debug('Could not retrieve finding {}'.format(finding_id))
            ErrorResponseModel('An error occurred.', 500, 'Could not retrieve finding {}'.format(finding_id))
    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')


@router.get('/repository/{repository_id}', response_description='Get all findings for repository by its id')
async def get_repository_findings(repository_id: str, token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        findings = await retrieve_all_findings_for_repository(repository_id=repository_id)
        if findings:
            logger.debug("All findings for {} retrieved successfully".format(repository_id))
            return SimpleResponseModel(findings, 'All findings for "{}" retrieved successfully'.format(repository_id))
        else:
            logger.debug('Could not retrieve findings for {}'.format(repository_id))
            ErrorResponseModel('An error occurred.', 500, 'Could not retrieve findings for {}'.format(repository_id))
    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')

#####################################
# PUT
#####################################

@router.put('/{finding_id}/fp', response_description='Update false-positive-assignment')
async def put_false_positive(finding_id: str, update_finding_model: UpdateFindingModelFalsePositive = Body(...), token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        update_result = await set_false_positive(finding_id=finding_id, update_false_positive=update_finding_model)
        if update_result.modified_count == 1:
            logger.debug("Updating {} modified count == 1".format(finding_id))
            finding = await retrieve_single_finding(finding_id=finding_id)
            if finding:
                logger.debug('Finding {} updated successfully'.format(finding_id))
                return UpdateResponseModel(finding, 'Finding "{}" updated successfully'.format(finding_id))
            else:
                logger.debug('Something went wrong after updating and receiving finding {}'.format(finding_id))
        logger.debug('Could not update finding {}'.format(finding_id))
        return ErrorResponseModel('An error occurred.', 500, 'Could not update finding "{}"'.format(finding_id))
    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')


@router.put('/{finding_id}/fav', response_description='Update favourite-status')
async def put_favourite(finding_id: str, update_finding_model: UpdateFindingModelFavourite = Body(...), token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        update_result = await set_favourite(finding_id=finding_id, update_false_positive=update_finding_model)

        if update_result.modified_count == 1:
            logger.debug("Updating {} modified count == 1".format(finding_id))
            finding = await retrieve_single_finding(finding_id=finding_id)
            if finding:
                logger.debug('Finding {} updated successfully'.format(finding_id))
                return UpdateResponseModel(finding, 'Finding {} updated successfully'.format(finding_id))
            else:
                logger.debug('Something went wrong after updating and receiving finding {}'.format(finding_id))
        logger.debug('Could not update finding {}'.format(finding_id))
        return ErrorResponseModel('An error occurred.', 500, 'Could not update finding "{}"'.format(finding_id))
    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')


#####################################
# POST
#####################################

@router.post('/raw_upload', response_description='Upload new findings')
async def post_findings_raw(upload_findings: List[UploadNewFindingModelRaw] = Body(...), token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        await upload_new_findings(new_findings=upload_findings)
    else:
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')

@router.post('/file_upload', response_description='Upload new list of findings')
async def post_finding_file(new_file: UploadFile, file_meta_data: UploadNewFindingModelForm = Depends(), token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        try:
            new_file = await upload_new_finding_file(new_file=new_file)
            if new_file:
                logger.debug("New file uploaded")
                return SimpleResponseModel(data=new_file, code=201, message='File was created successfully')
            else:
                logger.debug("Could not upload new file")
        except ValueError as e:
            logger.debug("An exception occured uploading new file: {}".format(str(e)))
            raise HTTPException(status_code=422, detail='Unprocessable Entity -> {}'.format(e))
        except OSError as e:
            logger.debug("An exception occured uploading new file: {}".format(str(e)))
            raise HTTPException(status_code=422, detail='Unprocessable Entity -> {}'.format(e))
    else:
        logger.debug("Rejected unauthenticated api call")
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')
