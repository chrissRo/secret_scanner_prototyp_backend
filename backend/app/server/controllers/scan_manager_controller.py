#####################################
# GET
#####################################
import logging

from app.server.fs_scan_results.fs_scan_results_manager import FSScanResultsManager
from app.server.models.finding_models.finding_model import UploadNewFindingModelForm

logger = logging.getLogger(__name__)

async def start_file_import(file: str, file_meta_data: UploadNewFindingModelForm):

    results = await FSScanResultsManager().run(
        scanner=file_meta_data.scannerType,
        scanner_version=file_meta_data.scannerVersion,
        file=file)
    if results:
        logger.debug("Return {} results from file import".format(len(results)))
        return results
    else:
        logger.debug("Return 0 results from file import".format(len(results)))
        return None
