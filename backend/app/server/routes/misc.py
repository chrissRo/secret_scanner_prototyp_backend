import logging
from fastapi import APIRouter, Depends

from app.globals.global_config import AvailableScanner
from app.server.auth.auth import auth
from app.server.models.finding_models.finding_model import ErrorResponseModel

logger = logging.getLogger(__name__)


router = APIRouter()

#####################################
# GET Available Scanner
#####################################

@router.get('/scanner', response_description='Get supported scanner-types')
async def get_scanner_types(token=Depends(auth.oauth2scheme)):
    if await auth.is_authenticated(token=token):
        return {s.name: s.value for s in AvailableScanner}
    else:
        logger.debug("Rejected unauthenticated api call")
        ErrorResponseModel('An error occurred.', 500, 'Could not fetch supported scanner-types')
