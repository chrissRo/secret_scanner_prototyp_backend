import argparse
import asyncio
import datetime
import logging
import os.path
import sys

import uvicorn

from app.globals.global_config import AvailableScanner, InputType
from app.server.fs_scan_results.fs_scan_results_manager import FSScanResultsManager
from app.server.models.finding_models.finding_model import UploadNewFindingModel
from app.user.user_manager import UserManager
from config.config import LoggerConfig, GitleaksConfig

logger = logging.getLogger(__name__)

def init():
    if not(os.path.exists(GitleaksConfig.FS_RAW_INPUT_PATH)):
        logging.debug("Creating input-dir {}".format(GitleaksConfig.FS_RAW_INPUT_PATH))
        os.makedirs(GitleaksConfig.FS_RAW_INPUT_PATH)
    else:
        logging.debug("Input-dir {} already exists".format(GitleaksConfig.FS_RAW_INPUT_PATH))


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--start-webserver', required=False, help='Start uvicorn webserver', action='store_true')
    parser.add_argument('--bulk-upload', required=False, help='Start bulk-upload of data', action='store_true')

    logging.basicConfig(
        level=LoggerConfig.LOG_LEVEL,
        filename=LoggerConfig.LOG_FILE,
        filemode=LoggerConfig.FILE_MODE,
        format=LoggerConfig.LOG_FORMAT
    )
    init()

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.start_webserver:
        logging.debug('Starting webserver and application')

        asyncio.run(UserManager().run())

        print("Backend is running ...")
        uvicorn.run(
            "app.server.app:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_config='config/uvicornConfig.yml'
        )
    else:
        if args.bulk_upload:
            logging.debug("Starting file-upload")

            fs_scan_results_manager = FSScanResultsManager()
            asyncio.run(fs_scan_results_manager.run(meta_data=UploadNewFindingModel(
                scannerType=AvailableScanner.GITLEAKS,
                scannerVersion='8.15',
                inputType=InputType.FileSystem,
                repositoryPath=".",
                repositoryName='Manual-import',
                scanDate=datetime.datetime.now()
            )))
