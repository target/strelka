# Contributing to Strelka
Thank you so much for your interest in contributing to Strelka! This document contains guidelines to follow when contributing to the project.

## Code of Conduct
The Code of Conduct can be reviewed [here](https://github.com/target/strelka/blob/master/CODE_OF_CONDUCT.md).

## Submitting Changes
Pull requests should be submitted using the pull request template. Changes will be validated by the project maintainers before merging to master.

## Submitting Bugs
Bugs should be submitted as issues using the bug report template.

## Submitting Enhancements
Enhancements should be submitted as issues using the feature request template.

## Development Environment

Clone the repo

```
git clone https://github.com/target/strelka.git
```

Python should be set up to use a virtualenv.

```
cd strelka/
python -m venv env
```

Activate the virtualenv

```
source env/bin/activate
```

Install build requirements

```
cd src/python/
pip install -r requirements.txt
```

Install strelka

```
python setup.py install
```

Install pre-commit hooks

```
pre-commit install
```


Development builds can tested using the default docker-compose.yaml file (`build/docker-compose.yaml`). To bring the project up with docker-compse, use the following command as a template:
    ```bash
    docker-compose -f build/docker-compose.yaml --project-name strelka up
    ```

## Testing
We rely on contributors to test any changes before they are submitted as pull requests. Any components added or changed should be tested and tests documented in the pull request. To assist in testing, the project maintainers may ask for file samples.

### PyTest

New scanners should be accompanied by a [pytest](https://docs.pytest.org/) based test in `src/python/strelka/tests`, along with **non-malicous** and reasonably sized sample files in `src/python/strelka/tests/fixtures`.

New fixtures should also be accompanied by updates to the configuration tests in `tests_configuration`. Changes to tastes or scanner assignments will require updates to these tests.

The best way to run Strelka's test suite is to build the docker containers. Some of Strelka's scanners have OS level dependencies which make them unsuitable for individual testing.

```
docker-compose -f build/docker-compose.yaml build

============================= test session starts ==============================
platform linux -- Python 3.10.6, pytest-7.2.0, pluggy-1.0.0
rootdir: /strelka
plugins: mock-3.10.0, unordered-0.5.2
collected 92 items

tests/test_required_for_scanner.py .
tests/test_scan_base64.py .
tests/test_scan_base64_pe.py .
tests/test_scan_batch.py .
tests/test_scan_bmp_eof.py .

...

tests/test_scan_upx.py .
tests/test_scan_url.py ..
tests/test_scan_vhd.py ..
tests/test_scan_x509.py ..
tests/test_scan_xml.py .
tests/test_scan_yara.py .
tests/test_scan_zip.py ..

======================= 92 passed, 29 warnings in 27.93s =======================
```

If you're testing with the default backend.yaml and taste.yara, enable `CONFIG_TESTS` to assure the configuration works as expected.

```
docker-compose -f build/docker-compose.yaml build --build-arg CONFIG_TESTS=true backend

============================= test session starts ==============================
platform linux -- Python 3.10.6, pytest-7.2.0, pluggy-1.0.0
rootdir: /strelka
plugins: mock-3.10.0, unordered-0.5.2
collected 155 items

tests_configuration/test_scanner_assignment.py .............................................................................
tests_configuration/test_taste.py ..............................................................................

======================= 155 passed, 4 warnings in 8.55s ========================
```

## Style Guides

### Python
Python code should attempt to adhere as closely to [PEP8](https://www.python.org/dev/peps/pep-0008/) as possible.

Conformance is ensured using `black`, `isort`, `flake8`, and `mypy` in pre-commit hooks and CI/CD actions. Pushes and PRs may be automatically rejected due to non-conformance. Review errors/warnings from the style modules for tips.

### Scanners
* Write event data in snake_case JSON format
* Write event data as early as possible during a scan
* Write known date-time values in ISO 8601 (up to seconds) whenever possible
    ```py
    self.event["timestamp"] = datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(timespec="seconds")
    ```
* Prioritize reading file data in this order:
  * Bytes
  ```py
  mime_type = magic.from_buffer(data, mime=True)
  ```
  * BytesIO
  ```py
  with io.BytesIO(data) as bzip2_obj:
  ```
  * tempfile
  ```py
  with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
      tmp_data.write(data)
      tmp_data.flush()
  ```
* Add appropriate try/except statements and append the exceptions as flags with lower case, underscore style
  ```py
  try:
    ...
  except ValueError:
    self.flags.append(f"value_error_{object_id}")
  except PDFObjectNotFound:
    self.flags.append(f"object_not_found_{object_id}")
  except PDFNotImplementedError:
    self.flags.append(f"not_implemented_error_{object_id}")
  except PSSyntaxError:
    self.flags.append(f"ps_syntax_error_{object_id}")
  ```
* If catching bare `Exception`, always catch and raise strelka.ScannerTimeout
  ```py
    try:
      ...
    except strelka.ScannerTimeout:
      raise
    except Exception:
      self.flags.append(f"unknown_bad_thing_happened")
  ```
* Add a `total` dictionary if a scanner can extract more than 1 file from the file being scanned
    * This dictionary should be as contextual as possible and include the number of successfully extracted files
    ```py
    self.event["total"] = {"scripts": 0, "forms": 0, "inputs": 0, "frames": 0, "extracted": 0}
    ```
* If possible, do not alter the file content of child files
  * If file content needs to be altered, then it should happen at scan time and not during creation
* Choose literal child filenames over contextual child filenames whenever possible
  ```py
  if part_filename is not None:
      child_filename = f"{part_filename}"
      ...
  else:
      child_filename = f"part_{index}"
  ```
* If a parent file is adding external event data to a child file during its creation, then the external event key should be formatted `<name of parent>_<name of field>`
  ```py
  rar_event_data = {"scan_rar_host_os": HOST_OS_MAPPING[child_info.host_os]}
  ```
* Don't write event data that can create limitless fields -- use an array of dictionary entries
    * These dictionary entries should be as contextual as possible (i.e. `{"segment": "foo", "sections": "bar"}` is better than `{"key": "foo", "value": "bar"}`)
