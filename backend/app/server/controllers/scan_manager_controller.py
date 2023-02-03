#####################################
# GET
#####################################

from app.server.fs_scan_results.fs_scan_results_manager import FSScanResultsManager
from app.server.models.finding_models.finding_model import UploadNewFindingModelForm


async def start_file_import(file: str, file_meta_data: UploadNewFindingModelForm):

    results = await FSScanResultsManager().run(
        scanner=file_meta_data.scannerType,
        scanner_version=file_meta_data.scannerVersion,
        file=file)
    if results:
        return results
    else:
        return None
