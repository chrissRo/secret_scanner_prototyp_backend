import asyncio

import uvicorn

from app.globals.global_config import AvailableScanner
from app.server.fs_scan_results.fs_scan_results_manager import FSScanResultsManager

if __name__ == "__main__":
    uvicorn.run(
        "app.server.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        ssl_keyfile='../certificate/backend.key',
        ssl_certfile='../certificate/backend.pem'
        )

    #fs_scan_results_manager = FSScanResultsManager(scanner=AvailableScanner.GITLEAKS, scanner_version='8.15')
    #asyncio.run(fs_scan_results_manager.run())

