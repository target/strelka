# Authors: Ryan Borre

import xlrd
import xlrd2
from enum import Enum
from os import devnull


class VISIBILITY(Enum):
    VISIBLE = 0
    HIDDEN = 1
    VERYHIDDEN = 2


class SHEET_TYPE(Enum):
    WORKSHEET = 16
    MACROSHEET = 64


class XLSWrapper:

    def __init__(self, file_path):
        try:
            self.workbook = xlrd2.open_workbook(file_path, logfile=open(devnull, 'w'))
        except xlrd2.biffh.XLRDError:
            return
        except xlrd2.compdoc.CompDocError:
            return
        except AssertionError:
            return
        except UnicodeDecodeError:
            return

    def get_defined_names(self):
        defined_names = list()
        for index, (name_obj, cells) in enumerate(self.workbook.name_map.items()):
            if cells[0].result:
                defined_names.append(name_obj)

        return defined_names

    def parse_sheets(self, file_path):
        results = {
            'sheets': []
        }
        formula_count = 0
        value_count = 0
        sheet_count = 0

        for sheet_name in self.workbook.sheet_names():
            sheet_count += 1
            formulas = []
            values = []
            sheet_xls = self.workbook.sheet_by_name(sheet_name)

            for row in range(0, sheet_xls.nrows):
                for col in range(0, sheet_xls.ncols):
                    try:
                        if self.workbook[sheet_name].cell(row, col).ctype in (3, 4):
                            formula_count += 1
                            formulas.append({
                                "cell": xlrd.formula.cellname(row, col),
                                "value": self.workbook[sheet_name].cell(row, col).formula
                            })
                        elif self.workbook[sheet_name].cell(row, col).ctype in (1, 2):
                            value_count += 1
                            values.append({
                                "cell": xlrd.formula.cellname(row, col),
                                "value": self.workbook[sheet_name].cell(row, col).value
                            })
                    except:
                        pass

            results['sheets'].append({
                'sheet_number': self.workbook[sheet_name].number,
                'sheet_name': self.workbook[sheet_name].name,
                'sheet_type': SHEET_TYPE(self.workbook[sheet_name].boundsheet_type).name,
                'visibility': VISIBILITY(self.workbook[sheet_name].visibility).name,
                'formulas': formulas,
                'values': values,
            })

        results['defined_names'] = self.get_defined_names()
        results['meta'] = {
            'formulas': formula_count,
            'values': value_count,
            'sheets': sheet_count,
            'defined_names': len(results['defined_names'])
        }

        return results
