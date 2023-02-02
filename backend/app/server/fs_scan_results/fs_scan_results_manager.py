import json
import pathlib
import sys

from fastapi.encoders import jsonable_encoder
from datetime import datetime

from pydantic import ValidationError

from app.globals.global_config import AvailableScanner, InputType
from app.server import database
from app.server.database import findings_collection
from app.server.models.finding_models.false_positive import FalsePositiveModel
from app.server.models.finding_models.finding_model import FindingModel
from app.server.models.finding_models.gitleaks_raw_result import GitleaksRawResultModel
from config.config import GitleaksConfig, InitialModelValue
import os

"""
speichere nur Einträge in die Datenbank, die dort noch nicht als false-positive hinterlegt wurden 
anschließend können die neuen Ergebnisse für eine Evaluierung bereitgestellt werden 
"""


class FSScanResultsManager:
    _raw_results = []
    _transformed_results = []
    _already_stored_in_db = []
    _validation_errors = []
    _value_errors = []
    _false_positives = []
    _db_client = None
    _findings_ids = []
    _scanner = ''
    _scanner_version = ''

    def __init__(self):
        self._raw_input_path = GitleaksConfig.FS_RAW_INPUT_PATH
        _db_client = database.db_client

    async def run(self, scanner: AvailableScanner, scanner_version: str, file=None) -> [{}]:
        if scanner.value == AvailableScanner.GITLEAKS.value:
            self._scanner = scanner.GITLEAKS
            self._scanner_version = scanner_version

            if file:
                self.read_raw_input_file(file=file)
            else:
                self.read_raw_input()
            self.transform_raws_to_finding_model()
            await self.remove_already_stored_from_transformed()
            db_results = await self.write_results_to_db()
            if db_results:
                db_results = db_results.inserted_ids
            else:
                db_results = []

            print(self._already_stored_in_db)
            return {
                'db_results': db_results,
                'already_stored': self._already_stored_in_db
            }
        else:
            # Todo Error Handling
            pass

    def read_raw_input_file(self, file):
        try:
            # check if json
            if not file.endswith(GitleaksConfig.FS_RAW_INPUT_FILE_TYPE):
                raise FileExistsError
            self.read_file(file=file)
        except FileNotFoundError as e:
            # Todo Error Handling
            print(e)
        except FileExistsError as e:
            # Todo Error Handling
            print(e)
            print('No JSON-File found')

    def read_raw_input(self):
        raw_json_files = []
        try:
            raw_files = [f for f in os.listdir(self._raw_input_path) if
                         os.path.isfile(os.path.join(self._raw_input_path, f))]
            # filter for json
            raw_json_files = [f for f in raw_files if pathlib.Path(f).suffix == GitleaksConfig.FS_RAW_INPUT_FILE_TYPE]
        except FileNotFoundError as e:
            # Todo Error Handling
            print(e)

        for file in raw_json_files:
            self.read_file(file=file)

    def read_file(self, file):
        with open(file=os.path.join(self._raw_input_path, file), mode='r') as f:
            try:
                data = json.load(f)
                if data:
                    scan_date, repo_name, repo_path = file.split('__')
                    repo_name = pathlib.Path(repo_name).stem
                    self._raw_results.append({"scan_date": scan_date, "repo_name": repo_name, "data": data, "repo_path": repo_path})
            except ValueError:
                # Todo Error Handling
                print("Invalid JSON for: {}".format(repo_name))
                self._value_errors.append(f.name)

    async def remove_already_stored_from_transformed(self):

        not_yet_stored = []

        await self.get_all_false_positive()

        for entry in self._transformed_results:
            if not await self.is_already_stored(entry):
                not_yet_stored.append(entry)
            else:
                print("Already stored: {}".format(entry.resultRaw.Fingerprint))
                self._already_stored_in_db.append(str(entry.id))
        self._transformed_results = not_yet_stored

    def is_false_positive(self, entry: FindingModel) -> bool:
        # check if entry is already stored as false_positive in database
        # get all entries in db that are marked as false-positive

        for false_positive in self._false_positives:
            print(false_positive)
            if false_positive['resultRaw']['Fingerprint'] == entry.resultRaw.Fingerprint:
                return True
        return False

    async def is_already_stored(self, entry: FindingModel) -> bool:
        # check if entry is already stored in database
        # if yes do not store it
        # use fingerprint
        db_entry = await findings_collection.find_one({'resultRaw.Fingerprint': entry.resultRaw.Fingerprint})
        if db_entry:
            return True
        return False

    async def get_all_false_positive(self):

        cursor = findings_collection.find({'falsePositive.isFalsePositive': True})
        docs = await cursor.to_list(length=1)
        self._false_positives.extend(docs)
        while docs:
            docs = await cursor.to_list(length=100)
            if docs:
                self._false_positives.extend(docs)

    def transform_raws_to_finding_model(self):
        for scan in self._raw_results:
            for raw_result in scan['data']:
                try:
                    self._transformed_results.append(FindingModel(scannerType=self._scanner.value,
                                                                  inputType=InputType.FileSystem,
                                                                  repositoryPath=scan['repo_path'],
                                                                  repositoryName=scan["repo_name"],
                                                                  scanStartTime=datetime.fromisoformat(scan["scan_date"]),
                                                                  scanEndTime=datetime.fromisoformat(scan["scan_date"]),
                                                                  resultRaw=GitleaksRawResultModel(
                                                                      **raw_result),
                                                                  falsePositive=FalsePositiveModel(
                                                                      justification=InitialModelValue.JUSTIFICATION),
                                                                  scannerVersion=self._scanner_version,
                                                                  save_date=datetime.today()))
                except ValidationError as e:
                    # Todo Error Handling
                    print("Validation Error for: {}".format(scan["repo_name"]))
                    self._validation_errors.append(raw_result)
                    print(e)
                except ValueError as e:
                    # Todo Error Handling
                    #print("Value Error for: {}".format(scan))
                    self._value_errors.append(raw_result)
                    print(e)

    async def get_findings_from_db(self) -> []:
        findings = []
        for finding_id in self._findings_ids:
            findings.append(await findings_collection.find_one({'_id': finding_id}))
        return findings

    async def write_results_to_db(self) -> []:
        if self._transformed_results:
            return await findings_collection.insert_many(jsonable_encoder(self._transformed_results))
