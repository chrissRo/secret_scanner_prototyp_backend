import json

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

async def retrieve_overview_data() -> list:
    overview = []
    async for repo in findings_collection.aggregate([{"$group": {"_id": "$repositoryName"}}]):
        # now we have the distinct repo-names
        # and we can select data to each repository by name
        #repo_data = await findings_collection.find({"repositoryName": repo['_id']}, {'repositoryPath': 1, 'scanEndTime': 1, 'scannerType': 1, 'scannerVersion': 1}).to_list(length=None)
        # get only latest scan

        overview.append(await findings_collection.find({"repositoryName": repo['_id']}, {'repositoryPath': 1, 'scanEndTime': 1, 'scannerType': 1, 'scannerVersion': 1}).sort('scanEndTime', -1).limit(1).to_list(length=None))

    return overview

async def retrieve_overview_data_count() -> dict:
    data_count = {
        'total_number_of_documents': 0,
        'total_number_of_distinct_repos': 0,
        'documents_per_repository': []

    }
    async for total_number_of_docs in findings_collection.aggregate([{"$count": "total_number_of_documents"}]):
        print(total_number_of_docs)
        data_count['total_number_of_documents'] = total_number_of_docs
    async for repo_count in findings_collection.aggregate([{'$group': {'_id': '$repositoryName', 'count': {'$count': {}}}}]):

        data_count['documents_per_repository'].append(repo_count)
    distinct_repos = await findings_collection.distinct('repositoryName')
    data_count['total_number_of_distinct_repos'] = len(distinct_repos)

    return data_count

###########################
# PUT
#####################################

# update false-positive
async def set_false_positive(finding_id: str, update_false_positive: UpdateFindingModel):
    return await findings_collection.update_one({'_id': finding_id}, {'$set': jsonable_encoder(update_false_positive)})

