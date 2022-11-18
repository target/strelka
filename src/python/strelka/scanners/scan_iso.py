import io
import collections
import datetime
import pycdlib

from pycdlib.dates import DirectoryRecordDate
from strelka import strelka


class ScanIso(strelka.Scanner):
    """Extracts files from ISO files."""

    def scan(self, data, file, options, expire_at):
        file_limit = options.get('limit', 1000)

        self.event['total'] = {'files': 0, 'extracted': 0}
        self.event['files'] = []
        self.event['hidden_dirs'] = []
        self.event['meta'] = {}

        try:
            # ISO must be opened as a byte stream
            with io.BytesIO(data) as iso_io:
                iso = pycdlib.PyCdlib()
                iso.open_fp(iso_io)

                # Attempt to get Meta
                try:
                    self.event['meta']['date_created'] = self._datetime_from_volume_date(iso.pvd.volume_creation_date)
                    self.event['meta']['date_effective'] = self._datetime_from_volume_date(iso.pvd.volume_effective_date)
                    self.event['meta']['date_expiration'] = self._datetime_from_volume_date(iso.pvd.volume_expiration_date)
                    self.event['meta']['date_modification'] = self._datetime_from_volume_date(iso.pvd.volume_modification_date)
                    self.event['meta']['volume_identifier'] = iso.pvd.volume_identifier.decode()
                except:
                    pass

                if iso.has_udf():
                    pathname = 'udf_path'
                elif iso.has_rock_ridge():
                    pathname = 'rr_path'
                elif iso.has_joliet():
                    pathname = 'joliet_path'
                else:
                    pathname = 'iso_path'

                root_entry = iso.get_record(**{pathname: '/'})

                # Iterate through ISO file tree
                dirs = collections.deque([root_entry])
                while dirs:
                    dir_record = dirs.popleft()
                    ident_to_here = iso.full_path_from_dirrecord(dir_record,
                                                                 rockridge=pathname == 'rr_path')
                    if dir_record.is_dir():
                        # Try to get hidden files, not applicable to all iso types
                        try:
                            if dir_record.file_flags == 3:
                                self.event['hidden_dirs'].append(ident_to_here)
                        except:
                            pass

                        child_lister = iso.list_children(**{pathname: ident_to_here})

                        for child in child_lister:
                            if child is None or child.is_dot() or child.is_dotdot():
                                continue
                            dirs.append(child)
                    else:
                        try:
                            # Collect File Metadata
                            self.event['files'].append({'filename': ident_to_here,
                                                        'size': iso.get_record(**{pathname: ident_to_here}).data_length,
                                                        'date_utc': self._datetime_from_iso_date(
                                                            iso.get_record(**{pathname: ident_to_here}).date)})

                            # Extract ISO Files (If Below Option Limit)
                            if self.event['total']['extracted'] < file_limit:
                                try:
                                    self.event['total']['files'] += 1
                                    file_io = io.BytesIO()
                                    iso.get_file_from_iso_fp(file_io, **{pathname: ident_to_here})
                                    extract_file = strelka.File(
                                        name=ident_to_here,
                                        source=self.name,
                                    )
                                    file_io.seek(0)
                                    extract_data = file_io.read()
                                    for c in strelka.chunk_string(extract_data):
                                        self.upload_to_coordinator(
                                            extract_file.pointer,
                                            c,
                                            expire_at,
                                        )
                                    self.files.append(extract_file)
                                    self.event['total']['extracted'] += 1
                                except Exception as e:
                                    self.flags.append(f'iso_extract_error: {e}')
                        except Exception:
                            self.flags.append('iso_read_error')
                iso.close()
        except Exception:
            self.flags.append('iso_read_error')

    @staticmethod
    def _datetime_from_volume_date(volume_date):
        """Helper method for converting VolumeRecordDate to string time."""
        try:
            year = volume_date.year
            month = volume_date.month
            day = volume_date.dayofmonth
            hour = volume_date.hour
            minute = volume_date.minute
            second = volume_date.second

            dt = datetime.datetime(
                year,
                month,
                day,
                hour,
                minute,
                second,
            )
            return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        except:
            return

    @staticmethod
    def _datetime_from_iso_date(iso_date):
        """Helper method for converting DirectoryRecordDate to string ISO8601 time."""
        try:
            if isinstance(iso_date, DirectoryRecordDate):
                year = 1900 + iso_date.years_since_1900
                day = iso_date.day_of_month
            else:
                return

            if not year:
                return

            if year < 1970:
                year += 100

            month = iso_date.month
            if iso_date.month == 0:
                month = 1

            try:
                dt = datetime.datetime(
                    year,
                    month,
                    day,
                    iso_date.hour,
                    iso_date.minute,
                    iso_date.second,
                )
                dt = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
            except Exception:
                return
            return dt
        except:
            return
