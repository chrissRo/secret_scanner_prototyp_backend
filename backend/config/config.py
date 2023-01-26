

class GitleaksConfig:

    FS_RAW_INPUT_PATH = 'test/gitleaks_input' # relative to main.py
    FS_RAW_INPUT_FILE_TYPE = '.json'
    FS_FILE_NAME_MODEL = '<YYYY-MM-DD>__<repository_name>' # 2021-08-21__cp-middleware.json ISO-Format

class InitialModelValue:
    JUSTIFICATION = 'init'


class JWTConfig:
    ALGORITHM = 'HS256'
    ACCESS_TOKEN_EXPIRE_MINUTES = 60
    ISSUER = 'Team ISS'
