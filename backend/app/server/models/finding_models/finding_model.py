from datetime import datetime
from typing import Union, List

from fastapi import Form
from pydantic import BaseModel, Field, validator, StrictBool

from utils.PyObjectId import PyObjectId
from app.server.models.finding_models.gitleaks_raw_result import GitleaksRawResultModel
from app.server.models.finding_models.raw_result import RawResultModel
from app.server.models.finding_models.false_positive import FalsePositiveModel, UpdateFalsePositive
from app.globals.global_config import AvailableScanner, InputType
from utils.helpers import form_body


class FindingModel(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    scannerType: AvailableScanner
    scannerVersion: str = Field(...)
    inputType: InputType
    repositoryPath: str = Field(...)
    repositoryName: str = Field(...)
    scanStartTime: datetime = Field(...)
    scanEndTime: datetime = Field(...)
    save_date: datetime = Field(...)
    isFavourite: StrictBool = False
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


class UpdateFindingModelFavourite(BaseModel):
    isFavourite: StrictBool

    class Config:
        allow_population_by_field_name = True
        json_encoders = {PyObjectId: str}
        arbitrary_types_allowed = True

@form_body
class UploadNewFindingModelForm(BaseModel):
    scannerType: AvailableScanner = Form(...)
    scannerVersion: str = Form(...)
    inputType: InputType = InputType.API
    repositoryPath: str = Form(...)
    repositoryName: str = Form(...)
    scanDate: datetime = Form(...)

    class Config:
        allow_population_by_field_name = True
        json_encoders = {PyObjectId: str}
        arbitrary_types_allowed = True

class UploadNewFindingModel(BaseModel):
    scannerType: AvailableScanner
    scannerVersion: str
    inputType: InputType
    repositoryPath: str
    repositoryName: str
    scanDate: datetime

    class Config:
        allow_population_by_field_name = True
        json_encoders = {PyObjectId: str}
        arbitrary_types_allowed = True

class UploadNewFindingModelRaw(BaseModel):
    scannerType: AvailableScanner = Field(...)
    scannerVersion: str = Field(...)
    inputType: InputType = InputType.API
    repositoryPath: str = Field(...)
    repositoryName: str = Field(...)
    scanDate: datetime = Field(...)
    resultRaw: List[Union[GitleaksRawResultModel]] = Field(...)

    class Config:
        allow_population_by_field_name = True
        json_encoders = {PyObjectId: str}
        arbitrary_types_allowed = True

def ResponseModel(data, message, code=200):
    return {
        "data": [data],
        "code": code,
        "message": message,
    }

def UpdateResponseModel(data, message):
    return {
        "data": data,
        "code": 200,
        "message": message,
    }

def SimpleResponseModel(data, message, code=200):
    return {
        "data": data,
        "code": code,
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
