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

        try:
            with io.BytesIO(data) as iso_io:
                iso = pycdlib.PyCdlib()
                iso.open_fp(iso_io)

                root_entry = iso.get_record(**{'iso_path': '/'})

                dirs = collections.deque([root_entry])
                while dirs:
                    dir_record = dirs.popleft()
                    ident_to_here = iso.full_path_from_dirrecord(dir_record,
                                                                 rockridge='iso_path' == 'rr_path')
                    if dir_record.is_dir():
                        child_lister = iso.list_children(**{'iso_path': ident_to_here})

                        for child in child_lister:
                            if child is None or child.is_dot() or child.is_dotdot():
                                continue
                            dirs.append(child)
                    else:
                        try:
                            self.event['files'].append({'filename': ident_to_here,
                                            'size': iso.get_entry(ident_to_here).data_length,
                                            'date_utc': self._datetime_from_iso_date(iso.get_entry(ident_to_here).date)})
                            if self.event['total']['extracted'] < file_limit:
                                try:
                                    file_io = io.BytesIO()
                                    iso.get_file_from_iso_fp(file_io, iso_path=ident_to_here)
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
    def _datetime_from_iso_date(iso_date):
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
