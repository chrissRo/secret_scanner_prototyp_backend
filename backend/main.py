import asyncio
import logging

import uvicorn

from app.user.user_manager import UserManager
from config.config import LoggerConfig

if __name__ == "__main__":

    logging.basicConfig(
        level=LoggerConfig.LOG_LEVEL,
        filename=LoggerConfig.LOG_FILE,
        filemode=LoggerConfig.FILE_MODE,
        format=LoggerConfig.LOG_FORMAT
    )

    logging.debug('Start Application')

    asyncio.run(UserManager().run())

    uvicorn.run(
        "app.server.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_config='config/uvicornConfig.yml'
        )

    #fs_scan_results_manager = FSScanResultsManager(scanner=AvailableScanner.GITLEAKS, scanner_version='8.15')
    #asyncio.run(fs_scan_results_manager.run())

