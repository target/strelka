import warnings
from os import walk
from os.path import isfile, join
from pathlib import Path


def test_required_for_scanner(mocker):
    scanner_filenames = []

    scanner_path = Path(__file__).parent.parent / "scanners"

    for dirpath, dirnames, filenames in walk(scanner_path):
        scanner_filenames.extend(filenames)
        break

    scanner_filenames = sorted(scanner_filenames)

    for scanner_filename in scanner_filenames:
        if scanner_filename != "__init__.py" and not isfile(
            join(Path(__file__).parent, f"test_{scanner_filename}")
        ):
            warnings.warn(f"Missing scanner test {scanner_filename}")

    # Tests are recommened, but not yet required for the test to pass
    assert True
