import logging

from fastapi import Form

from config.config import GitleaksConfig

logger = logging.getLogger(__name__)

def clear_input_directory():
    import os
    import shutil
    logger.debug("Cleaning directory {}".format(GitleaksConfig.FS_RAW_INPUT_PATH))
    files = os.listdir(GitleaksConfig.FS_RAW_INPUT_PATH)
    logger.debug("Found {} files to remove".format(len(files)))
    for filename in files:
        logger.debug("Cleaning input directory from file {}".format(filename))
        file_path = os.path.join(GitleaksConfig.FS_RAW_INPUT_PATH, filename)
        if os.path.isfile(file_path) or os.path.islink(file_path):
            os.unlink(file_path)
        elif os.path.isdir(file_path):
            shutil.rmtree(file_path)


def form_body(cls):
    cls.__signature__ = cls.__signature__.replace(
        parameters=[
            arg.replace(default=Form(...))
            for arg in cls.__signature__.parameters.values()
        ]
    )
    return cls
