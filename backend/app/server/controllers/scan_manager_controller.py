#####################################
# GET
#####################################
import json
import logging

from app.server.fs_scan_results.fs_scan_results_manager import FSScanResultsManager
from app.server.models.finding_models.finding_model import UploadNewFindingModelForm, UploadNewFindingModel

logger = logging.getLogger(__name__)


async def start_file_import(file: str, file_meta_data: UploadNewFindingModelForm):
    results = await FSScanResultsManager().run(
        meta_data=UploadNewFindingModel(scannerType=file_meta_data.scannerType,
                                        scannerVersion=file_meta_data.scannerVersion,
                                        inputType=file_meta_data.inputType,
                                        repositoryPath=file_meta_data.repositoryPath,
                                        repositoryName=file_meta_data.repositoryName,
                                        scanDate=file_meta_data.scanDate
                                        ),
        file=file
    )
    if results:
        logger.debug("Return {} results from file import".format(len(results['db_results'])))
        return results
    else:
        logger.debug("Return 0 results from file import")
        return None
