import asyncio

import uvicorn

from app.user.user_manager import UserManager

if __name__ == "__main__":

    asyncio.run(UserManager().run())

    uvicorn.run(
        "app.server.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True
        )

    #fs_scan_results_manager = FSScanResultsManager(scanner=AvailableScanner.GITLEAKS, scanner_version='8.15')
    #asyncio.run(fs_scan_results_manager.run())

