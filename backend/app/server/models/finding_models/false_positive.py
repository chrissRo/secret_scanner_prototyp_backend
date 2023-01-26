from datetime import datetime
from pydantic import BaseModel, Field, validator, StrictBool

from config.config import InitialModelValue


class FalsePositiveModel(BaseModel):

    isFalsePositive: StrictBool = False
    justification: str = Field(...)
    change_date: datetime = '1900-01-01 00:00:00.000000'
    
    @validator('justification')
    def false_positive_needs_justification(cls, value):
        if value == '':
            raise ValueError('Please provide justification for falsePositive')
        else:
            return value


class UpdateFalsePositive(BaseModel):

    isFalsePositive: StrictBool = False
    justification: str = Field(...)
    change_date: datetime

    @validator('justification')
    def false_positive_needs_justification(cls, value):
        if value == '' or value == InitialModelValue.JUSTIFICATION:
            raise ValueError('Please provide a reason for change the falsePositive-Status')
        else:
            return value

    @validator('change_date')
    def set_change_date(cls, value):
        return datetime.now()
