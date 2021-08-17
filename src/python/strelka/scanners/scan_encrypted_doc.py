import io
import os
import msoffcrypto
import subprocess
import tempfile

from strelka import strelka

def crack_word(self, data, jtr_path, tmp_dir, password_file, max_length=10, scanner_timeout=150, brute=False):
	try:
		with tempfile.NamedTemporaryFile(dir=tmp_dir, mode='wb') as tmp_data:
			tmp_data.write(data)
			tmp_data.flush()
			
			(office2john, stderr) = subprocess.Popen(
				[jtr_path+'office2john.py', tmp_data.name],
				stdout=subprocess.PIPE,
				stderr=subprocess.DEVNULL
			).communicate()
		
		with tempfile.NamedTemporaryFile(dir=tmp_dir) as tmp_data:
			tmp_data.write(office2john)
			tmp_data.flush()

			(stdout, stderr) = subprocess.Popen(
				[jtr_path+'john', '--show', tmp_data.name],
				stdout=subprocess.PIPE,
				stderr=subprocess.DEVNULL
			).communicate()

		if b"0 password hashes cracked" in stdout:

			with tempfile.NamedTemporaryFile(dir=tmp_dir) as tmp_data:
				tmp_data.write(office2john)
				tmp_data.flush()
			
				if os.path.isfile(password_file):
					(stdout, stderr) = subprocess.Popen(
						[jtr_path+'john', f'-w={password_file}', tmp_data.name],
						stdout=subprocess.PIPE,
						stderr=subprocess.DEVNULL
					).communicate(timeout=scanner_timeout)
					
					if stdout.split(b'\n')[3]:
						self.flags.append('cracked_by_wordlist')
						return stdout.split(b'\n')[3].split()[0]

				if brute:
					(stdout, stderr) = subprocess.Popen(
						[jtr_path+'john', '--incremental=Alnum', f'--max-length={max_length}', f'--max-run-time={scanner_timeout}', tmp_data.name],
						stdout=subprocess.PIPE,
						stderr=subprocess.DEVNULL
					).communicate(timeout=scanner_timeout)
					if stdout.split(b'\n')[3]:
						self.flags.append('cracked_by_incremental')
						return stdout.split(b'\n')[3].split()[0]
				return ''
		else:
			return stdout.split(b':')[1].split()[0]

	except Exception as e:
		self.flags.append(str(e))
		return ''

class ScanEncryptedDoc(strelka.Scanner):
	"""Extracts passwords from encrypted office word documents.

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
		log_extracted_pws = options.get('log_pws', True)
		scanner_timeout = options.get('scanner_timeout', 150)
		brute = options.get('brute_force', False)
		max_length = options.get('max_length', 5)

		with io.BytesIO(data) as doc_io:

			msoff_doc = msoffcrypto.OfficeFile(doc_io)
			output_doc = io.BytesIO()
			if extracted_pw := crack_word(self, data, jtr_path, tmp_directory, brute=brute, scanner_timeout=scanner_timeout, max_length=max_length, password_file=password_file):
				self.event['cracked_password'] = extracted_pw
				try:
					msoff_doc.load_key(password=extracted_pw.decode('utf-8'))
					msoff_doc.decrypt(output_doc)
					output_doc.seek(0)
					extract_data = output_doc.read()
					output_doc.seek(0)
					extract_file = strelka.File(
					source=self.name,
					)

					for c in strelka.chunk_string(extract_data):
						self.upload_to_coordinator(
							extract_file.pointer,
							c,
							expire_at,
						)

					self.files.append(extract_file)
				except:
					self.flags.append('Could not decrypt document with recovered password')

			else:
				self.flags.append('Could not extract password')