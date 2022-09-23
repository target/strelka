import os
import sys
import string
import struct
import hashlib
import datetime
import traceback

from bits.structs import FILE, CONTROL, JOB

from strelka.cstructs.bits.ese import ESENT_DB
from strelka import strelka


# XFER_HEADER defined as bytes
XFER_HEADER = b'\x36\xDA\x56\x77\x6F\x51\x5A\x43\xAC\xAC\x44\xA2\x48\xFF\xF3\x4D'


# File and job delimiter constants for Windows 10
WIN10_FILE_DELIMITER = b'\xE4\xCF\x9E\x51\x46\xD9\x97\x43\xB7\x3E\x26\x85\x13\x05\x1A\xB2'
WIN10_JOB_DELIMITERS = [
    b'\xA1\x56\x09\xE1\x43\xAF\xC9\x42\x92\xE6\x6F\x98\x56\xEB\xA7\xF6',
    b'\x9F\x95\xD4\x4C\x64\x70\xF2\x4B\x84\xD7\x47\x6A\x7E\x62\x69\x9F',
    b'\xF1\x19\x26\xA9\x32\x03\xBF\x4C\x94\x27\x89\x88\x18\x95\x88\x31',
    b'\xC1\x33\xBC\xDD\xFB\x5A\xAF\x4D\xB8\xA1\x22\x68\xB3\x9D\x01\xAD',
    b'\xd0\x57\x56\x8f\x2c\x01\x3e\x4e\xad\x2c\xf4\xa5\xd7\x65\x6f\xaf',
    b'\x50\x67\x41\x94\x57\x03\x1d\x46\xa4\xcc\x5d\xd9\x99\x07\x06\xe4'
]

class ScanBITS(strelka.Scanner):
    """Collects metadata and extracts files from Windows BITS files."""

    def scan(self, data, file, options, expire_at):
        self.event['jobs'] = []

        try:
            self.event['jobs'] = self.process_file(data)
        except Exception:
            self.flags.append("file_parsing_error")

    def process_file(self, file_data):
        """ Processes the given BITS file.  Attempts to find/parse jobs. """

        try:

            # Parse as a qmgr database (support old and Win10 formats)
            parsed_records = []
            jobs = self.load_qmgr10_db(file_data)
            for job in jobs:
                try:
                    parsed_records.append(job.job_dict)
                except:
                    self.flags.append("job_parsing_error")
            if parsed_records:
                return parsed_records

        except Exception as e:
            print(e)

    def parse_qmgr10_job(self, file_entries, job_data):
        """Attempt to parse job data from the Win10 qmgr database"""
        # Skip small entires that are not valid
        if len(job_data) < 128:
            return None
        try:

            # Because it can be expensive to parse a JOB structure if the data is not valid,
            # do a simple check to see if the job name length is valid
            name_length = struct.unpack_from("<L", job_data, 32)[0]
            if 32 + name_length * 2 > len(job_data):
                return None

            # Parse as a JOB
            try:
                parsed_job = JOB.parse(job_data)
            except Exception:
                # If it fails to parse as a JOB, at least try to parse as a CONTROL struct
                try:
                    parsed_job = CONTROL.parse(job_data)
                except Exception:
                    return None

            try:
                # Following the JOB entry, there are usually XFER refs to FILE GUIDs
                parsed_job['files'] = []
                xfer_parts = job_data.split(XFER_HEADER)
                file_ref_data = xfer_parts[1]
                num_file_refs = struct.unpack_from("<L", file_ref_data)[0]
                # Validate the number of file references to avoid expensive parsing failures
                if 4 + num_file_refs * 16 > len(file_ref_data):
                    return None
                for i in range(0, num_file_refs):
                    # Parse the GUID and attempt to find correlated FILE
                    cur_guid = file_ref_data[4 + i * 16:4 + (i + 1) * 16]
                    file_job = file_entries.pop(cur_guid, None)
                    if file_job:
                        parsed_job['files'].extend(file_job['files'])
            except Exception:
                pass

            # Build a BitsJob for the job entry
            new_job = BitsJob(parsed_job)
            return new_job
        except Exception:
            print(f'Exception occurred parsing job: ' + traceback.format_exc(), file=sys.stderr)
            return None

    def parse_qmgr10_file(self, file_data, suppress_duplicates):
        """Attempt to parse file data from the Win10 qmgr database"""

        # Skip small entires that are not valid
        if len(file_data) < 256:
            return None
        try:
            # Because it can be expensive to parse a FILE structure if the data is not valid,
            # do a simple check to see if the filename length is valid
            filename_length = struct.unpack_from("<L", file_data)[0]
            if 4 + filename_length * 2 > len(file_data):
                return None

            # Parse the FILE
            parsed_file = FILE.parse(file_data)

            # Build a BitsJob for the file entry (set entry as files list)
            cur_job = {}
            cur_job['files'] = [parsed_file]

            # There is usually a timestamp 29 bytes into the file structure, which appears to correlate to creation time
            filetime = struct.unpack_from("<Q", file_data, parsed_file.offset + 29)[0]
            if filetime != 0:
                cur_job['ctime'] = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=(filetime / 10))

            return cur_job
        except Exception:
            return None

    def load_qmgr10_db(self, file_data):
        """Loads the qmgr.db and attempts to enumerate the Jobs and Files tables to parse records"""
        jobs = []
        file_entries = {}

        # Parse the database
        ese = ESENT_DB(file_data)

        # Enumerate files, store file entries to file_entries mapping
        files_table = ese.openTable("Files")
        while True:
            file_record = ese.getNextRow(files_table)
            if file_record is None:
                break
            guid = file_record.get(b'Id')
            new_job = self.parse_qmgr10_file(file_record.get(b'Blob', b''), False)
            if guid and new_job:
                file_entries[guid] = new_job

        # Enumerate jobs (and correlate to files)
        jobs_table = ese.openTable("Jobs")
        while True:
            job_record = ese.getNextRow(jobs_table)
            if job_record is None:
                break
            guid = job_record.get(b'Id')
            job_data = job_record.get(b'Blob', b'')[16:]
            new_job = self.parse_qmgr10_job(file_entries, job_data)
            if guid and new_job:
                jobs.append(new_job)

        # If any file records were not correlated to JOBs just add them as their own jobs
        for guid, file_job in file_entries.items():
            jobs.append(BitsJob(file_job))

        return jobs

class BitsJob:
    """
    Provides methods for reformatting parsed jobs from the ANSSI-FR library
    """

    # Mappings between types returned by ANSSI-FR library and our output fields
    FILE_MAP = dict(
        src_fn="SourceURL",
        dest_fn="DestFile",
        tmp_fn="TmpFile",
        download_size="DownloadByteSize",
        transfer_size="TransferByteSize",
        vol_guid="VolumeGUID"
    )

    JOB_MAP = dict(
        job_id="JobId",
        type="JobType",
        priority="JobPriority",
        state="JobState",
        name="JobName",
        desc="JobDesc",
        cmd="CommandExecuted",
        args="CommandArguments",
        sid="OwnerSID",
        ctime="CreationTime",
        mtime="ModifiedTime",
        carved="Carved",
        files="Files",
        queue_path="QueuePath"
    )


    def __init__(self, job):
        """ Initialize a BitsJob with a parsed job dictionary and a reference to BitsParser """
        self.job = job
        self.hash = None

        self.job_dict = {}

        self.parse()


    def is_useful_for_analysis(self, cur_dict=None):
        """ Returns True if the job contains at least one "useful" field (discards useless "carved" entries) and the ctime field exists """
        useful_fields = ['SourceURL', 'DestFile', 'TmpFile', 'JobId', 'JobState', 'CommandExecuted', 'CommandArguments']

        if not cur_dict:
            cur_dict = self.job_dict

        for k, v in cur_dict.items():
            if k in useful_fields and v:
                return True
            # Handle lists of dicts, like we have for the Files field
            if isinstance(v, list):
                for d in v:
                    if self.is_useful_for_analysis(d):
                        return True
        return False


    def is_carved(self):
        """ Simple function returns True if the job was carved """
        return self.job_dict.get('Carved') is True


    @staticmethod
    def escape(input_str):
        """ Simple escape function to eliminating non-printable characters from strings """
        if not isinstance(input_str, str) or input_str.isprintable():
            return input_str
        return ''.join(filter(lambda x: x in string.printable, input_str))


    def parse(self):
        """
        Converts the fields in self.job into format used for output and separates file entries.
        Does some formatting and type conversion.  Also computes a hash of the job for quick comparison.
        """

        file_fields = ['args', 'cmd', 'dest_fn', 'tmp_fn']
        job_hash = hashlib.md5()
        for k, v in self.job.items():
            # Map the attribute name, skip empty or unmapped values
            alias = self.JOB_MAP.get(k)
            if not alias:
                continue
            elif not v or str(v).strip() == '':
                continue

            # Convert timestamps into normal isoformat
            elif isinstance(v, datetime.datetime):
                self.job_dict[alias] = v.replace(microsecond=0).isoformat() + 'Z'

            # Convert boolean values to lowercase
            elif isinstance(v, bool):
                self.job_dict[alias] = str(v).lower()


            # The files field contains a list of files -- perform attribute mapping and environment variable resolution
            elif alias == self.JOB_MAP['files']:
                files_list = []
                for file in v:
                    file_dict = {}
                    for k1, v1 in file.items():

                        # Map the transaction attribute name, skip empty, unmapped, or invalid values
                        t_alias = self.FILE_MAP.get(k1)
                        if not t_alias:
                            continue
                        elif v1 is None or str(v1).strip() == '' or not str(v1).isprintable():
                            continue

                        # Skip certain invalid values (if there is no value or if the value is -1 (DWORD64))
                        if v1 is None or v1 == 0xFFFFFFFFFFFFFFFF:
                            continue

                        # If this is a file field, resolve and add to the list of files
                        if k1 in file_fields:
                            file_dict[t_alias] = os.path.expandvars(v1)
                        else:
                            file_dict[t_alias] = v1

                        # Update the object hash
                        job_hash.update(str(file_dict[t_alias]).encode('utf-8'))
                    files_list.append(file_dict)

                self.job_dict['Files'] = files_list
            else:
                self.job_dict[alias] = v

            # Escape non-printable chars if appropriate
            self.job_dict[alias] = self.escape(self.job_dict[alias])

            # Update the object hash
            if type(v) != 'Dict':
                job_hash.update(str(v).encode('utf-8'))

        self.hash = job_hash.hexdigest()
