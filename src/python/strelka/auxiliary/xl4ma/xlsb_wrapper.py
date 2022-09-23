# Authors: Ryan Borre

import xlrd
from pyxlsb2 import open_workbook
from pyxlsb2.formula import Formula


class XLSBWrapper:

    def __init__(self, file_path):
        try:
            self.workbook = open_workbook(file_path)
        except Exception as e:
            return

    def get_defined_names(self):
        defined_names = list()
        for name, obj in self.workbook.defined_names.items():
            defined_names.append(name)

        return defined_names

    def parse_sheets(self, file_path):
        results = {
            'sheets': []
        }
        formula_count = 0
        value_count = 0
        sheet_count = 0

        for sheet in self.workbook.sheets:
            sheet_count += 1
            formulas = []
            values = []
            try:
                for row in self.workbook.get_sheet_by_name(sheet.name):
                    for cell in row:
                        if cell.formula:
                            formula_count += 1
                            formulas.append({
                                'cell': xlrd.formula.cellname(cell.row.num, cell.col),
                                'value': Formula.parse(cell.formula).stringify(self.workbook)
                            })
                        elif cell.value and not cell.formula:
                            value_count += 1
                            values.append({
                                'cell': xlrd.formula.cellname(cell.row.num, cell.col),
                                'value': cell.value
                            })
            except:
                pass
            results['sheets'].append({
                'sheet_number': sheet.sheetId,
                'sheet_name': sheet.name,
                'sheet_type': sheet.type.upper(),
                'visibility': sheet.state.name,
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
