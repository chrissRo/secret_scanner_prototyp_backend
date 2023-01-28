from config.config import GitleaksConfig


def clear_input_directory():
    import os
    import shutil
    for filename in os.listdir(GitleaksConfig.FS_RAW_INPUT_PATH):
        file_path = os.path.join(GitleaksConfig.FS_RAW_INPUT_PATH, filename)
        if os.path.isfile(file_path) or os.path.islink(file_path):
            os.unlink(file_path)
        elif os.path.isdir(file_path):
            shutil.rmtree(file_path)

