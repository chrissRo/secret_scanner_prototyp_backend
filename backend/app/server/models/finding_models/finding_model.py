from datetime import datetime
from typing import Union
from pydantic import BaseModel, Field, DirectoryPath, validator, StrictBool

from config.config import InitialModelValue
from utils.PyObjectId import PyObjectId
from app.server.models.finding_models.gitleaks_raw_result import GitleaksRawResultModel
from app.server.models.finding_models.raw_result import RawResultModel
from app.server.models.finding_models.false_positive import FalsePositiveModel, UpdateFalsePositive
from app.globals.global_config import AvailableScanner, InputType


class FindingModel(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    scannerType: AvailableScanner
    scannerVersion: str = Field(...)
    inputType: InputType
    repositoryPath: DirectoryPath = Field(...)
    repositoryName: str = Field(...)
    scanStartTime: datetime = Field(...)
    scanEndTime: datetime = Field(...)
    save_date: datetime = Field(...)
    isFavorite: StrictBool = False
    resultRaw: Union[GitleaksRawResultModel] = Field(...)
    falsePositive: FalsePositiveModel = Field(...)

    @validator('resultRaw')
    def check_raw_type(cls, value):
        if issubclass(type(value), RawResultModel):
            return value
        else:
            raise TypeError('Wrong type for resultRaw. Must be of type RawResult')

    class Config:
        allow_population_by_field_name = True
        json_encoders = {PyObjectId: str}


class UpdateFindingModel(BaseModel):
    falsePositive: FalsePositiveModel = Field(...)

    class Config:
        allow_population_by_field_name = True
        json_encoders = {PyObjectId: str}
        arbitrary_types_allowed = True


class UpdateFindingModelFalsePositive(BaseModel):
    falsePositive: UpdateFalsePositive = Field(...)

    class Config:
        allow_population_by_field_name = True
        json_encoders = {PyObjectId: str}
        arbitrary_types_allowed = True

def ResponseModel(data, message):
    return {
        "data": [data],
        "code": 200,
        "message": message,
    }

def UpdateResponseModel(data, message):
    return {
        "data": data,
        "code": 200,
        "message": message,
    }

def SimpleResponseModel(data, message):
    return {
        "data": data,
        "code": 200,
        "message": message,
    }

# 'repositoryName':'', 'repositoryPath', 'lastScan', 'numberOfFindingsInDB
def OverviewResponseModel(data: [{}], message):
    return {
        "data": data,
        "code": 200,
        "message": message
    }

def ErrorResponseModel(error, code, message):
    return {
        "error": error,
        "code": code,
        "message": message
    }
