import subprocess
import tempfile
import io
import os
import zipfile
import zlib

from strelka import strelka

def crack_zip(self, data, jtr_path, tmp_dir, password_file, brute=False, max_length=10, scanner_timeout=150):
		try:
				with tempfile.NamedTemporaryFile(dir=tmp_dir, mode='wb') as tmp_data:
						tmp_data.write(data)
						tmp_data.flush()
						
						(zip2john, stderr) = subprocess.Popen(
								[jtr_path+'zip2john', tmp_data.name],
								stdout=subprocess.PIPE,
								stderr=subprocess.DEVNULL
						).communicate()
				
				with tempfile.NamedTemporaryFile(dir=tmp_dir) as tmp_data:
						tmp_data.write(zip2john)
						tmp_data.flush()

						(stdout, stderr) = subprocess.Popen(
								[jtr_path+'john', '--show', tmp_data.name],
								stdout=subprocess.PIPE,
								stderr=subprocess.DEVNULL
						).communicate()

				if b"0 password hashes cracked" in stdout:

						with tempfile.NamedTemporaryFile(dir=tmp_dir) as tmp_data:
								tmp_data.write(zip2john)
								tmp_data.flush()
						
								if os.path.isfile(password_file):
										(stdout, stderr) = subprocess.Popen(
												[jtr_path+'john', f'-w={password_file}', tmp_data.name],
												stdout=subprocess.PIPE,
												stderr=subprocess.DEVNULL
										).communicate(timeout=scanner_timeout)
										
										if stdout.split(b'\n')[1]:
												self.flags.append('cracked_by_wordlist')
												return stdout.split(b'\n')[1].split()[0]
								if brute:
									(stdout, stderr) = subprocess.Popen(
											[jtr_path+'john', '--incremental=Alnum', f'--max-length={max_length}', f'--max-run-time={scanner_timeout}', tmp_data.name],
											stdout=subprocess.PIPE,
											stderr=subprocess.DEVNULL
									).communicate(timeout=scanner_timeout)
									if stdout.split(b'\n')[1]:
										self.flags.append('cracked_by_incremental')
										return stdout.split(b'\n')[1].split()[0]
								return ''
				else:
						return stdout.split(b':')[1]

		except Exception as e:
				self.flags.append(str(e))
				return ''


class ScanEncryptedZip(strelka.Scanner):
		"""Extracts passwords from encrypted ZIP archives.

		Attributes:
				passwords: List of passwords to use when bruteforcing encrypted files.

		Options:
				limit: Maximum number of files to extract.
						Defaults to 1000.
				password_file: Location of passwords file for zip archives.
						Defaults to /etc/strelka/passwords.dat.
		"""

		def scan(self, data, file, options, expire_at):
				
				jtr_path = options.get('jtr_path', '/jtr/')
				tmp_directory = options.get('tmp_file_directory', '/tmp/')
				file_limit = options.get('limit', 1000)
				password_file = options.get('password_file', '/etc/strelka/passwords.dat')
				log_extracted_pws = options.get('log_pws', False)
				scanner_timeout = options.get('scanner_timeout', 150)
				brute = options.get('brute_force', False)
				max_length = options.get('max_length', 5)

				self.event['total'] = {'files': 0, 'extracted': 0}

				with io.BytesIO(data) as zip_io:
						try:
								with zipfile.ZipFile(zip_io) as zip_obj:
										name_list = zip_obj.namelist()
										self.event['total']['files'] = len(name_list)

										extracted_pw = crack_zip(self, data, jtr_path, tmp_directory, brute=brute, scanner_timeout=scanner_timeout, max_length=max_length, password_file=password_file)
										if not extracted_pw:
												self.flags.append('Could not extract password')
												return
										if log_extracted_pws:
												self.event['cracked_password'] = extracted_pw
										for i, name in enumerate(name_list):
												if not name.endswith('/'):
														if self.event['total']['extracted'] >= file_limit:
																break

														try:
																extract_data = zip_obj.read(name, extracted_pw)

																if extract_data:
																		extract_file = strelka.File(
																				name=name,
																				source=self.name,
																		)

																		for c in strelka.chunk_string(extract_data):
																				self.upload_to_coordinator(
																						extract_file.pointer,
																						c,
																						expire_at,
																				)

																		self.files.append(extract_file)
																		self.event['total']['extracted'] += 1

														except NotImplementedError:
																self.flags.append('unsupported_compression')
														except RuntimeError:
																self.flags.append('runtime_error')
														except ValueError:
																self.flags.append('value_error')
														except zlib.error:
																self.flags.append('zlib_error')

						except zipfile.BadZipFile:
								self.flags.append('bad_zip')