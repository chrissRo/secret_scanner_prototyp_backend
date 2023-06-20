import json
import logging
import pathlib
import os
from fastapi.encoders import jsonable_encoder
from datetime import datetime
from pydantic import ValidationError
from app.globals.global_config import AvailableScanner, InputType
from app.server import database
from app.server.database import findings_collection
from app.server.models.finding_models.false_positive import FalsePositiveModel
from app.server.models.finding_models.finding_model import FindingModel, \
    UploadNewFindingModel
from app.server.models.finding_models.gitleaks_raw_result import GitleaksRawResultModel
from config.config import GitleaksConfig, InitialModelValue

"""
speichere nur Einträge in die Datenbank, die dort noch nicht als false-positive hinterlegt wurden 
anschließend können die neuen Ergebnisse für eine Evaluierung bereitgestellt werden 
"""

logger = logging.getLogger(__name__)


class FSScanResultsManager:
    _raw_results = []
    _transformed_results = []
    _already_stored_in_db = set()
    _validation_errors = []
    _type_errors = []
    _value_errors = []
    _false_positives = []
    _db_client = None
    _findings_ids = []
    _scanner = ''
    _scanner_version = ''
    _file_meta_data = {}
    _repository_hoster = ''
    _bulk_upload: bool

    def __init__(self):
        self._raw_input_path = GitleaksConfig.FS_RAW_INPUT_PATH
        _db_client = database.db_client

    def cleanup(self):
        logger.debug("Cleaning up FSScanResultsManager")
        self._raw_results.clear()
        self._transformed_results.clear()
        self._already_stored_in_db.clear()
        self._validation_errors.clear()
        self._type_errors.clear()
        self._value_errors.clear()
        self._false_positives.clear()
        self._db_client = None
        self._findings_ids.clear()
        self._scanner = ''
        self._scanner_version = ''
        self._repository_hoster = ''

    async def run(self, meta_data: UploadNewFindingModel, file=None, repository_hoster=None, bulk_upload=False) -> [{}]:
        self._file_meta_data = meta_data
        self._bulk_upload = bulk_upload
        logger.debug("Bulk-Upload set to {}".format(str(self._bulk_upload)))
        if repository_hoster:
            self._repository_hoster = repository_hoster
        if self._file_meta_data.scannerType.value == AvailableScanner.GITLEAKS.value:
            logger.debug("AvailableScanner is Gitleaks")
            self._scanner = AvailableScanner.GITLEAKS
            self._scanner_version = self._file_meta_data.scannerVersion

            if file:
                logger.debug("AvailableScanner is Gitleaks. Using FileInput with file {}".format(file))
                self.read_raw_input_file(file=file)
            else:
                logger.debug("AvailableScanner is Gitleaks. Using FileInput with default filepath {}".format(
                    GitleaksConfig.FS_RAW_INPUT_PATH))
                self.read_raw_input()
            self.transform_raws_to_finding_model()
            await self.remove_already_stored_from_transformed()
            db_results = await self.write_results_to_db()
            if db_results:
                logger.debug("{} entries written to DB".format(len(db_results.inserted_ids)))
                db_results = db_results.inserted_ids
            else:
                logger.debug("No entries written to DB")
                db_results = []

            logger.debug("Result:")
            run_result = {
                'db_results': db_results,
                'already_stored': self._already_stored_in_db,
                'errors': len(self._type_errors) + len(self._value_errors) + len(self._validation_errors)
            }
            logger.debug(run_result)
            self.cleanup()
            return run_result
        else:
            # Todo Error Handling
            logger.debug("Invalid AvailableScanner provided. Value was {} -> Skipping step ...".format(
                self._file_meta_data.scannerType.value))
            self.cleanup()
            raise ValueError("Invalid AvailableScanner provided")

    def read_raw_input_file(self, file):
        try:
            # check if json
            if not file.endswith(GitleaksConfig.FS_RAW_INPUT_FILE_TYPE):
                logger.debug("File {} does not end with .json".format(file))
                raise FileExistsError
            self.read_file(file=file)
        except FileNotFoundError as e:
            # Todo Error Handling
            logger.debug("File {} not found".format(file))
            logger.debug(e)
        except FileExistsError as e:
            # Todo Error Handling
            logger.debug('No JSON-File found')
            logger.debug(e)

    def read_raw_input(self):
        raw_json_files = []

        for root, _, files in os.walk(self._raw_input_path):
            try:
                for raw_file in files:

                    # filter for json
                    if pathlib.Path(raw_file).suffix == GitleaksConfig.FS_RAW_INPUT_FILE_TYPE:
                        raw_json_files.append(os.path.join(root, raw_file))
                        logger.debug("Current file is: {}".format(os.path.join(root, raw_file)))

            except FileNotFoundError as e:
                # Todo Error Handling
                logger.debug("File not found")
                logger.debug(e)

        logger.debug("Collected {} files for further processing".format(len(raw_json_files)))
        for file in raw_json_files:
            self.read_file(file=file)

    def read_file(self, file):
        if not self._bulk_upload:
            file = os.path.join(self._raw_input_path, file)

        with open(file=file, mode='r') as f:
            try:
                data = json.load(f)
                if data:
                    if self._bulk_upload:
                        full_path = pathlib.Path(file)
                        self._file_meta_data.repositoryName = full_path.stem # path_parts[-1].split(".")[0]
                        self._file_meta_data.repositoryPath = f"{self._repository_hoster}{str(full_path.parent).split(GitleaksConfig.FS_RAW_INPUT_PATH)[1]}"
                    logger.debug(
                        "Found valid JSON in file {}. Repository is {}".format(f, self._file_meta_data.repositoryName))
                    self._raw_results.append({
                        "scan_date": str(self._file_meta_data.scanDate),
                        "repo_name": self._file_meta_data.repositoryName,
                        "repo_path": self._file_meta_data.repositoryPath,
                        "data": data
                    })
            except ValueError:
                # Todo Error Handling
                logger.debug("Invalid JSON for: {}".format(f))
                self._value_errors.append(f.name)

    async def remove_already_stored_from_transformed(self):

        not_yet_stored = []

        await self.get_all_false_positive()

        for entry in self._transformed_results:
            if not await self.is_already_stored(entry):
                not_yet_stored.append(entry)
            else:
                logger.debug("Finding already stored: Fingerprint {}".format(entry.resultRaw.Fingerprint))
                self._already_stored_in_db.add(str(entry.id))
        self._transformed_results = not_yet_stored

    def is_false_positive(self, entry: FindingModel) -> bool:
        # check if entry is already stored as false_positive in database
        # get all entries in db that are marked as false-positive

        for false_positive in self._false_positives:
            logger.debug("False Positive:")
            logger.debug(false_positive)
            if false_positive['resultRaw']['Fingerprint'] == entry.resultRaw.Fingerprint:
                return True
        return False

    async def is_already_stored(self, entry: FindingModel) -> bool:
        # check if entry is already stored in database
        # if yes do not store it
        # use fingerprint
        db_entry = await findings_collection.find_one({'resultRaw.Fingerprint': entry.resultRaw.Fingerprint})
        if db_entry:
            logger.debug("Entry already in DB:")
            logger.debug(db_entry)
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
                                                                  scanStartTime=datetime.fromisoformat(
                                                                      scan["scan_date"]),
                                                                  scanEndTime=datetime.fromisoformat(scan["scan_date"]),
                                                                  resultRaw=GitleaksRawResultModel(
                                                                      **raw_result),
                                                                  falsePositive=FalsePositiveModel(
                                                                      justification=InitialModelValue.JUSTIFICATION),
                                                                  scannerVersion=self._scanner_version,
                                                                  save_date=datetime.today()))
                except TypeError as e:
                    # Todo Error Handling
                    logger.debug("Type Error for: {}".format(scan["repo_name"]))
                    self._type_errors.append(raw_result)
                    logger.debug(e)
                except ValidationError as e:
                    # Todo Error Handling
                    logger.debug("Validation Error for: {}".format(scan["repo_name"]))
                    self._validation_errors.append(raw_result)
                    logger.debug(e)
                except ValueError as e:
                    # Todo Error Handling
                    logger.debug("Value Error for: {}".format(scan["repo_name"]))
                    self._value_errors.append(raw_result)
                    logger.debug(e)

    async def get_findings_from_db(self) -> []:
        findings = []
        for finding_id in self._findings_ids:
            findings.append(await findings_collection.find_one({'_id': finding_id}))
        return findings

    async def write_results_to_db(self) -> []:
        if self._transformed_results:
            logger.debug("Will write {} entries to DB".format(len(self._transformed_results)))
            return await findings_collection.insert_many(jsonable_encoder(self._transformed_results))

