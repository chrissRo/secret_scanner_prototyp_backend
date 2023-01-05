from fastapi.encoders import jsonable_encoder
from ..database import findings_collection
# https://stackoverflow.com/questions/71467630/fastapi-issues-with-mongodb-typeerror-objectid-object-is-not-iterable
from app.server.models.finding_models.finding_model import FindingModel, UpdateFindingModel


#####################################
# GET
#####################################

# get all findings
async def retrieve_all_findings() -> list:
    findings = []
    async for finding in findings_collection.find():
        findings.append(finding)
    return findings

# get data to known ids
# Todo weitere filter-möglichkeiten, wie zum Beispiel scan-date oder creation-date
# oder nur hinterlegte false-positive
async def retrieve_findings(findings_ids: list) -> list:
    findings = []
    for finding_id in findings_ids:
        findings.append(await retrieve_single_finding(finding_id))
    return findings

# get single finding
async def retrieve_single_finding(finding_id: str) -> FindingModel:
    return await findings_collection.find_one({'_id': finding_id})


async def retrieve_overview_data_count() -> dict:
    return {
        'total_number_of_docs': await findings_collection.count_documents(),
    }
#####################################
# PUT
#####################################

# update false-positive
async def set_false_positive(finding_id: str, update_false_positive: UpdateFindingModel):
    return await findings_collection.update_one({'_id': finding_id}, {'$set': jsonable_encoder(update_false_positive)})

