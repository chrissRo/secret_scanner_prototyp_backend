from fastapi import APIRouter, Depends
from fastapi.params import Body

from app.server.auth.auth import auth
from app.server.controllers.findings_controller import retrieve_all_findings, set_false_positive, \
    retrieve_single_finding, retrieve_overview_data_count
from app.server.models.finding_models.finding_model import ResponseModel, ErrorResponseModel, UpdateFindingModel

router = APIRouter()


#####################################
# GET
#####################################

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
            return ResponseModel(finding, 'Finding {} retrieved successfully.'.format(finding_id))
        else:
            ErrorResponseModel('An error occurred.', 500, 'Could not retrieve finding {}')
    else:
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')

@router.get('/finding/overview', response_description='Get overview-data to all findings')
async def get_finding_overview(token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        pass
    else:
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')

@router.get('/finding/count', response_description='Get counted overview-data to all findings')
async def get_finding_overview_count(token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        data_count = await retrieve_overview_data_count()
        if data_count:
            return ResponseModel(data_count, 'Data count retrieved successfully')
        else:
            ErrorResponseModel('An error occurred.', 500, 'Could not calculate data count')
    else:
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')
#####################################
# PUT
#####################################

@router.put('/{finding_id}', response_description='Update false-positive-assignment')
async def put_false_positive(finding_id: str, update_finding_model: UpdateFindingModel = Body(...), token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        update_result = await set_false_positive(finding_id=finding_id, update_false_positive=update_finding_model)

        if update_result.modified_count == 1:
            finding = await retrieve_single_finding(finding_id=finding_id)
            return ResponseModel(finding, 'Finding updated successfully')
        return ErrorResponseModel('An error occurred.', 500, 'Could not update finding {}'.format(finding_id))
    else:
        return ErrorResponseModel(error='Invalid User', code=403, message='Please login')


