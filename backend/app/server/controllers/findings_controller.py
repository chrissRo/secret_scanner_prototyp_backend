import json
import os.path
from typing import List

from fastapi.encoders import jsonable_encoder

from config.config import GitleaksConfig
from utils import helpers
from ..database import findings_collection
# https://stackoverflow.com/questions/71467630/fastapi-issues-with-mongodb-typeerror-objectid-object-is-not-iterable
from app.server.models.finding_models.finding_model import FindingModel, \
    UpdateFindingModelFalsePositive, UpdateFindingModelFavourite, UploadNewFindingModel


#####################################
# GET
#####################################

# get all findings
async def retrieve_all_findings() -> list:
    findings = []
    async for finding in findings_collection.find():
        findings.append(finding)
    return findings

# oder nur hinterlegte false-positive
async def retrieve_findings(findings_ids: list) -> list:
    findings = []
    for finding_id in findings_ids:
        findings.append(await retrieve_single_finding(finding_id))
    return findings

# get single finding
async def retrieve_single_finding(finding_id: str) -> FindingModel:
    return await findings_collection.find_one({'_id': finding_id})

# get all findings for given repo-id/name
async def retrieve_all_findings_for_repository(repository_id: str) -> list:
    findings = []

    async for finding in findings_collection.find({'repositoryName': repository_id}):
        findings.append(finding)
    return findings

async def retrieve_overview_data() -> list:
    overview = []
    async for repo in findings_collection.aggregate([{"$group": {"_id": "$repositoryName"}}]):
        # now we have the distinct repo-names
        # and we can select data to each repository by name
        #repo_data = await findings_collection.find({"repositoryName": repo['_id']}, {'repositoryPath': 1, 'scanEndTime': 1, 'scannerType': 1, 'scannerVersion': 1}).to_list(length=None)
        # get only latest scan

        overview.append((await findings_collection.find({
            "repositoryName": repo['_id']},
            {'repositoryName': 1,
             'repositoryPath': 1,
             'scanEndTime': 1,
             'scannerType': 1,
             'scannerVersion': 1
             }).sort('scanEndTime', -1).limit(1).to_list(length=None))[0])

    return overview

async def retrieve_overview_data_count() -> dict:
    data_count = {
        'total_number_of_documents': 0,
        'total_number_of_distinct_repos': 0,
        'documents_per_repository': []
    }

    async for total_number_of_docs in findings_collection.aggregate([{"$count": "total_number_of_documents"}]):
        data_count['total_number_of_documents'] = total_number_of_docs['total_number_of_documents']

    async for repo_count in findings_collection.aggregate([{'$group': {'_id': '$repositoryName', 'count': {'$count': {}}}}]):
        data_count['documents_per_repository'].append(repo_count)

    distinct_repos = await findings_collection.distinct('repositoryName')
    data_count['total_number_of_distinct_repos'] = len(distinct_repos)
    return data_count

async def retrieve_overview_data_count_for_repository(repository_id: str) -> dict:
    data_count = {
        'total_number_of_documents': await findings_collection.count_documents({'repositoryName': repository_id}),
        'total_number_of_false_positives': await findings_collection.count_documents({
            '$and': [{'repositoryName': repository_id}, {'falsePositive.isFalsePositive': True}]
        }),
        'total_number_of_true_positives': await findings_collection.count_documents({
            '$and': [{'repositoryName': repository_id}, {'falsePositive.isFalsePositive': False}]
        }),
        'total_number_of_todos': await findings_collection.count_documents({
            '$and': [{'repositoryName': repository_id},
                     {'falsePositive.change_date': '1900-01-01 00:00:00.000000'},
                     {'falsePositive.justification': ''}]
        })
    }
    return data_count

###########################
# PUT
#####################################

# update false-positive
async def set_false_positive(finding_id: str, update_false_positive: UpdateFindingModelFalsePositive):
    return await findings_collection.update_one({'_id': finding_id}, {'$set': jsonable_encoder(update_false_positive)})

async def set_favourite(finding_id: str, update_false_positive: UpdateFindingModelFavourite):
    return await findings_collection.update_one({'_id': finding_id}, {'$set': jsonable_encoder(update_false_positive)})


###########################
# POST
#####################################

# add new findings
async def upload_new_findings(new_findings: List[UploadNewFindingModel]):
    try:
        helpers.clear_input_directory()
        for new_finding in jsonable_encoder(new_findings):
            file_name = '{}__{}.json'.format(new_finding['scanDate'], new_finding['repositoryName'])
            print(jsonable_encoder(new_finding))
            with open(file=os.path.join(GitleaksConfig.FS_RAW_INPUT_PATH, file_name), mode='w') as f:
                json.dump(new_finding['resultRaw'], f)
            # führe den Scan-Manager aus wie in der main.py
            # eigener API-Call um Zwischenergebnis zurückliefern zu können GET zB
    except OSError as e:
        print('Could not clear input directory -> {}'.format(e))

