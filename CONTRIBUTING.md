# Contributing to Strelka
Thank you so much for your interest in contributing to Strelka! This document includes guidelines to follow when contributing to the project.

## Code of Conduct
The Code of Conduct can be reviewed [here](https://github.com/target/strelka/blob/master/CODE_OF_CONDUCT.md).

## Submitting Changes
Pull requests should be submitted using the pull request template and follow the [branching style guide](#branching). Changes will be validated by the project maintainers before merging to master.

## Submitting Bugs
Bugs should be submitted as issues using the bug report template.

## Submitting Enhancements
Enhancements should be submitted as issues using the feature request template.

## Development Environment
We recommend using Docker as a development environment. If needed, a development container can be created based on the production Dockerfile.

Below are some quickstart commands for testing a development build using Docker:
  * Terminal 1:
  ```bash
  $ docker build -t strelka-dev .
  $ docker run --rm -v <path to your test files>:<path to those files in the container> strelka-dev strelka.py
  ```
  * Terminal 2:
  ```bash
  $ docker exec <container ID/name from Terminal 1> user_client.py --broker 127.0.0.1:5558 --path <path to any file shared in Terminal 1>
  $ docker exec -it <container ID/name from Terminal 1> cat /var/log/strelka/<worker ID>.log
  ```

## Testing
We rely on contributors to test any changes before they are submitted as pull requests. Any components added or changed should be tested and tests documented in the pull request. To assist in testing, the project maintainers may ask for file samples.

## Style Guides
### Python
Python code should attempt to adhere as closely to [PEP8](https://www.python.org/dev/peps/pep-0008/) as possible. We may ask authors to refactor code for better PEP8 compliance, but we do not enforce 100% compliance.

### Scanners
* Write internal metadata in camelCase JSON format (see: [Google's JSON style guide](https://google.github.io/styleguide/jsoncstyleguide.xml))
* Write metadata as early as possible during a scan
* Write known date-time values in ISO 8601 (up to seconds)
    ```py
    self.metadata["timestamp"] = datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(timespec="seconds")
    ```
* Prioritize reading file data in this order:
  * Bytes
  ```py
  mime_type = magic.from_buffer(file_object.data, mime=True)
  ```
  * BytesIO
  ```py
  with io.BytesIO(file_object.data) as bzip2_object:
  ```
  * tempfile
  ```py
  with tempfile.NamedTemporaryFile(dir=tmp_directory) as strelka_file:
      strelka_filename = strelka_file.name
      strelka_file.write(file_object.data)
      strelka_file.flush()
  ```
* Add appropriate try/except statements and append the exceptions as flags
  ```py
  try:
    ...
  except ValueError:
    file_object.flags.append(f"{self.scanner_name}::value_error_{object_id}")
  except PDFObjectNotFound:
    file_object.flags.append(f"{self.scanner_name}::object_not_found_{object_id}")
  except PDFNotImplementedError:
    file_object.flags.append(f"{self.scanner_name}::not_implemented_error_{object_id}")
  except PSSyntaxError:
    file_object.flags.append(f"{self.scanner_name}::ps_syntax_error_{object_id}")
  ```
* Add a `total` metadata dictionary if a scanner can extract more than 1 file from the file being scanned
    * This metadata dictionary should be as contextual as possible and include the number of successfully extracted files
    ```py
    self.metadata["total"] = {"scripts": 0, "forms": 0, "inputs": 0, "frames": 0, "extracted": 0}
    ```
* If possible, do not alter the file content of child files
  * If file content needs to be altered, then it should happen at scan time and not during creation
* Prepend child filenames with the scanner class name and `::`
  ```py
  filename=f"{self.scanner_name}::{name}"
  filename=f"{self.scanner_name}::script_{index}"
  ```
* Choose literal child filenames over contextual child filenames when available
  ```py
  if part_filename is not None:
      child_filename = f"{self.scanner_name}::{part_filename}"
      ...
  else:
      child_filename = f"{self.scanner_name}::part_{index}"
  ```
* Prepend flags with the scanner class name and `::`
  ```py
  file_object.flags.append(f"{self.scanner_name}::type_error")
  ```
* If a parent file is adding external metadata to a child file during its creation, then the external metadata key should be formatted `<name of parent><name of field>`
  ```py
  rar_metadata = {"scanRarHostOs": HOST_OS_MAPPING[child_info.host_os]}
  ```
* Don't write metadata that can create limitless fields -- use an array of dictionary entries
    * These dictionary entries should be as contextual as possible (i.e. `{"segment": "foo", "sections": "bar"}` is better than `{"key": "foo", "value": "bar"}`)
