# Authors: Ryan Borre

import logging
import formulas
import os


class Interpreter:

    def __init__(self, defined_names):
        self.results = set()
        self.defined_names = defined_names

    def eval_call(self, args, name):
        func_args = []
        for _, arg in enumerate(args):
            if isinstance(arg, formulas.functions.Array):
                if isinstance(arg.tolist(), list):
                    func_args.append(arg[0][0])
                if isinstance(arg.tolist(), str):
                    func_args.append(arg.tolist())
            if isinstance(arg, int):
                func_args.append(str(arg))
            if isinstance(arg, float):
                func_args.append(str(int(arg)))

        if func_args:
            self.results.add(f"={name}({', '.join(func_args)})")

    @staticmethod
    def eval_char(x):
        if isinstance(x, formulas.functions.Array):
            return chr(int(x))
        if isinstance(x, formulas.ranges.Ranges):
            return chr(int(x.value[0][0]))
        if isinstance(x, int):
            return chr(x)
        if isinstance(x, float):
            return chr(int(x))

    def eval_formula(self, args):
        if len(args) == 2:
            x, y = args
            if isinstance(x, formulas.ranges.Ranges) and isinstance(y, formulas.functions.Array):
                # y[0][0] = x.value[0][0]
                y[0][0] = str(x.value[0][0]).replace('"&"', '')
                self.results.add(y[0][0])
                return y[0][0]

            if isinstance(x, formulas.functions.Array) and isinstance(y, formulas.ranges.Ranges):
                # y.value[0][0] = x[0][0]
                y.value[0][0] = str(x[0][0]).replace('"&"', '')
                self.results.add(y.value[0][0])
                return y.value[0][0]

            if isinstance(x, formulas.ranges.Ranges) and isinstance(y, formulas.ranges.Ranges):
                # y.value[0][0] = x.value[0][0]
                y.value[0][0] = str(x.value[0][0]).replace('"&"', '')
                self.results.add(y.value[0][0])
                return y.value[0][0]

            if isinstance(x, str) and isinstance(y, formulas.functions.Array):
                y[0][0] = x
                self.results.add(y[0][0])
                return y[0][0]

            if isinstance(x, str) and isinstance(y, formulas.ranges.Ranges):
                y.value[0][0] = x
                self.results.add(y.value[0][0])
                return y.value[0][0]

    def eval_set_name(self, args):
        name, arg = args
        self.results.add(str(arg).replace('^', ''))
        return arg

    def eval_custom(self, args, name=""):
        func_args = []
        for _, arg in enumerate(args):
            if isinstance(arg, formulas.ranges.Ranges):
                func_args.append(str(arg.value[0][0]))
            if isinstance(arg, formulas.functions.Array):
                if isinstance(arg.tolist(), list):
                    func_args.append(arg[0][0])
                if isinstance(arg.tolist(), str):
                    func_args.append(arg.tolist())
            if isinstance(arg, str):
                func_args.append(str(arg).replace('^', ''))
            if isinstance(arg, int):
                func_args.append(str(arg))
            if isinstance(arg, float):
                func_args.append(str(int(arg)))

        if func_args:
            self.results.add(f"={name}({', '.join(func_args)})")
            return f"={name}({', '.join(func_args)})"

        self.results.add(f"={name}()")
        return f"={name}()"

    def eval_run(self, args):
        arg = args
        self.results.add(arg)

    def calculate(self, temp_file):
        FUNCTIONS = formulas.get_functions()
        FUNCTIONS['ALERT'] = lambda *args: None
        FUNCTIONS['ARGUMENT'] = lambda *args: None
        FUNCTIONS['BEEP'] = lambda *args: None
        FUNCTIONS['_XLFN.BITXOR'] = lambda *args: args[0] ^ args[1]
        FUNCTIONS['CALL'] = lambda *args: self.eval_call(args, 'CALL')
        FUNCTIONS['CHAR'] = lambda x: self.eval_char(x)
        FUNCTIONS['CLOSE'] = lambda *args: None
        FUNCTIONS['COUNTBLANK'] = lambda *args: None
        FUNCTIONS['DOCUMENTS'] = lambda *args: None
        FUNCTIONS['ECHO'] = lambda *args: None
        FUNCTIONS['END.IF'] = lambda *args: None
        FUNCTIONS['ERROR'] = lambda *args: None
        FUNCTIONS['EXEC'] = lambda *args: self.eval_custom(args, 'EXEC')
        FUNCTIONS['FORMULA'] = lambda *args: self.eval_formula(args)
        FUNCTIONS['FORMULA.ARRAY'] = lambda *args: self.eval_formula(args)
        FUNCTIONS['FORMULA.CONVERT'] = lambda *args: None
        FUNCTIONS['FORMULA.FILL'] = lambda *args: self.eval_formula(args)
        FUNCTIONS['GET.DOCUMENT'] = lambda *args: None
        FUNCTIONS['GET.NAME'] = lambda *args: None
        FUNCTIONS['GET.WORKSPACE'] = lambda *args: None
        FUNCTIONS['HALT'] = lambda *args: None
        FUNCTIONS['OPEN'] = lambda *args: None
        FUNCTIONS['REGISTER'] = lambda *args: self.eval_custom(args, 'REGISTER')
        FUNCTIONS['RESULT'] = lambda *args: None
        FUNCTIONS['RETURN'] = lambda *args: None
        FUNCTIONS['RUN'] = lambda *args: self.eval_run(args)
        FUNCTIONS['SET.NAME'] = lambda *args: self.eval_set_name(args)
        FUNCTIONS['SUBSTITUTE'] = lambda *args: None
        FUNCTIONS['T'] = lambda x: x
        FUNCTIONS['TEXT'] = lambda x, y: x
        FUNCTIONS['WAIT'] = lambda *args: None
        FUNCTIONS['WINDOW.MINIMIZE'] = lambda *args: None
        FUNCTIONS['WORKBOOK.HIDE'] = lambda *args: None

        for name in self.defined_names:
            if name.upper() not in FUNCTIONS:
                FUNCTIONS[name.upper()] = lambda *args: self.eval_custom(args, name=name)

        try:
            xl_model = formulas.ExcelModel().loads(temp_file.name).finish()
            results = xl_model.calculate()

            for result in filter(None, results.values()):
                if isinstance(result, formulas.ranges.Ranges):
                    self.results.add(str(result.value[0][0]))
                if isinstance(result, str):
                    self.results.add(str(result))

        except:
            logging.info("formula error")

        temp_file.close()
        os.unlink(temp_file.name)

        return self.results
