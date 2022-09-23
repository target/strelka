# Authors: Ryan Borre

import argparse
import logging
import os
import tempfile
from pathlib import Path
from strelka.auxiliary.xl4ma.extract import iocs
from strelka.auxiliary.xl4ma.xls_wrapper import XLSWrapper
from strelka.auxiliary.xl4ma.xlsb_wrapper import XLSBWrapper
from strelka.auxiliary.xl4ma.xlsm_wrapper import XLSMWrapper
from strelka.auxiliary.xl4ma.xl4decoder import decode


def _make_temp_file(data, file_type):
    with tempfile.NamedTemporaryFile(suffix=f".{file_type}", delete=False) as temp_file:
        temp_file.write(data)

    return temp_file


def _get_file_type(data):
    file_type = None

    if data[:2] == b'\xd0\xcf':
        file_type = 'xls'
    elif data[:2] == b'\x50\x4b':
        file_type = 'xlsx'
    if file_type == 'xlsx':
        if bytes('workbook.bin', 'ascii') in data:
            file_type = 'xlsb'
        if bytes('workbook.xml', 'ascii') in data:
            file_type = 'xlsm'

    temp_file = _make_temp_file(data, file_type)

    return temp_file, file_type


def process_data(data, filename):
    excel_doc = None
    temp_file, file_type = _get_file_type(data)
    file_path = temp_file.name

    results = dict()

    if file_type == 'xls':
        excel_doc = XLSWrapper(file_path)
    elif file_type == 'xlsb':
        excel_doc = XLSBWrapper(file_path)
    elif file_type == 'xlsm':
        excel_doc = XLSMWrapper(file_path)

    if not hasattr(excel_doc, 'workbook'):
        logging.debug('file not supported')
        return

    results.update(excel_doc.parse_sheets(file_path))
    results['meta'].update({
        'file_name': filename,
        'file_type': file_type
    })

    excel_doc_decoded = decode(file_path, file_type, results['defined_names'])

    results['decoded'] = excel_doc_decoded
    results['iocs'] = iocs(excel_doc_decoded)

    temp_file.close()
    os.unlink(temp_file.name)

    return results


def parse_args(args=None):
    parser = argparse.ArgumentParser(
        description='Excel4 Macro Analyzer'
    )
    parser.add_argument('--file', required=True, type=str, action='store', metavar='FILE_PATH', help="path to file")

    return parser.parse_args(args)


def main(args=None):
    args = parse_args(args)

    with open(args.file, 'rb') as fd:
        data = fd.read()

    process_data(data, filename=Path(args.file).name)


if __name__ == "__main__":
    main()
