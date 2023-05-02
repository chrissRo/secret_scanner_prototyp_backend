from datetime import datetime
from pydantic import BaseModel, Field, validator, StrictBool

from config.config import InitialModelValue


class FalsePositiveModel(BaseModel):

    isFalsePositive: StrictBool = True
    justification: str = Field(...)
    change_date: datetime = InitialModelValue.CHANGE_DATE
    
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
            raise ValueError('Please provide a justification for changing the falsePositive-Status')
        else:
            return value

    @validator('change_date')
    def set_change_date(cls, value):
        return datetime.now()
