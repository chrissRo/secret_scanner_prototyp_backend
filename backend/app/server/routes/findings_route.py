import json

from fastapi import APIRouter, Depends
from fastapi.encoders import jsonable_encoder
from fastapi.params import Body

from app.server.auth.auth import auth
from app.server.controllers.findings_controller import retrieve_all_findings, set_false_positive, \
    retrieve_single_finding, retrieve_overview_data_count, retrieve_overview_data, \
    retrieve_all_findings_for_repository, retrieve_overview_data_count_for_repository, set_favourite
from app.server.models.finding_models.finding_model import ResponseModel, ErrorResponseModel, \
    SimpleResponseModel, UpdateFindingModelFalsePositive, UpdateResponseModel, UpdateFindingModelFavourite

router = APIRouter()


#####################################
# GET
#####################################

@router.get('/count', response_description='Get counted overview-data for all findings')
async def get_finding_overview_count(token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        data_count = await retrieve_overview_data_count()
        if data_count:
            return SimpleResponseModel(data_count, 'Data count retrieved successfully')
        else:
            ErrorResponseModel('An error occurred.', 500, 'Could not calculate data count')
    else:
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')

@router.get('/repository/{repository_id}/count', response_description='Get counted overview-data for given repository')
async def get_finding_overview_count(repository_id: str, token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        data_count = await retrieve_overview_data_count_for_repository(repository_id)
        if data_count:
            return SimpleResponseModel(data_count, 'Data count for repository "{}" retrieved successfully'.format(repository_id))
        else:
            ErrorResponseModel('An error occurred.', 500, 'Could not calculate data count for {}'.format(repository_id))
    else:
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')

@router.get('/overview', response_description='Get overview-data to all findings')
async def get_finding_overview(token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        data = await retrieve_overview_data()
        return SimpleResponseModel(jsonable_encoder(data), "Data retrieved successfully")
    else:
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')

@router.get('/', response_description='Get all findings')
async def get_all_findings(token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        findings = await retrieve_all_findings()
        if findings:
            return ResponseModel(findings, 'All findings retrieved successfully')
        else:
            return ErrorResponseModel('An error occurred.', 500, 'Could not retrieve findings.')
    else:
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')


@router.get('/{finding_id}', response_description='Get single finding')
async def get_single_finding(finding_id: str, token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        finding = await retrieve_single_finding(finding_id=finding_id)
        if finding:
            return ResponseModel(finding, 'Finding "{}" retrieved successfully.'.format(finding_id))
        else:
            ErrorResponseModel('An error occurred.', 500, 'Could not retrieve finding {}'.format(finding_id))
    else:
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')


@router.get('/repository/{repository_id}', response_description='Get all findings for repository by its id')
async def get_repository_findings(repository_id: str, token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        findings = await retrieve_all_findings_for_repository(repository_id=repository_id)
        if findings:
            return SimpleResponseModel(findings, 'All findings for "{}" retrieved successfully.'.format(repository_id))
        else:
            ErrorResponseModel('An error occurred.', 500, 'Could not retrieve findings for {}'.format(repository_id))
    else:
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')

#####################################
# PUT
#####################################

@router.put('/{finding_id}/fp', response_description='Update false-positive-assignment')
async def put_false_positive(finding_id: str, update_finding_model: UpdateFindingModelFalsePositive = Body(...), token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        update_result = await set_false_positive(finding_id=finding_id, update_false_positive=update_finding_model)

        if update_result.modified_count == 1:
            finding = await retrieve_single_finding(finding_id=finding_id)
            return UpdateResponseModel(finding, 'Finding "{}" updated successfully'.format(finding_id))
        return ErrorResponseModel('An error occurred.', 500, 'Could not update finding "{}"'.format(finding_id))
    else:
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')


@router.put('/{finding_id}/fav', response_description='Update favourite-status')
async def put_favourite(finding_id: str, update_finding_model: UpdateFindingModelFavourite = Body(...), token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        update_result = await set_favourite(finding_id=finding_id, update_false_positive=update_finding_model)

        if update_result.modified_count == 1:
            finding = await retrieve_single_finding(finding_id=finding_id)
            return UpdateResponseModel(finding, 'Finding "{}" updated successfully'.format(finding_id))
        return ErrorResponseModel('An error occurred.', 500, 'Could not update finding "{}"'.format(finding_id))
    else:
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')

