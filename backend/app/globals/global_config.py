from enum import IntEnum


class AvailableScanner(IntEnum):
    GITLEAKS = 0
    TRUFFLEHOG = 1


class InputType(IntEnum):
    FileSystem = 0
    API = 1
