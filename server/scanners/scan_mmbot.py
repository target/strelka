import json

import zmq

from server import lib


class ScanMmbot(lib.StrelkaScanner):
    """Collects Visual Basic results from a lib running mmbotd.

    Options:
        lib: Network address and network port of the mmbotd lib.
            Defaults to 127.0.0.1:33907.
        timeout: Amount of time (in milliseconds) to wait for a response
            from the lib.
            Defaults to 10000 milliseconds.
    """
    def scan(self, file_object, options):
        lib = options.get('server', '127.0.0.1:33907')
        timeout = options.get('timeout', 10000)

        context = zmq.Context()
        socket = context.socket(zmq.REQ)
        socket.setsockopt(zmq.LINGER, 0)
        socket.connect(f'tcp://{server}')
        socket.send_string(file_object.data.decode())
        poller = zmq.Poller()
        poller.register(socket, zmq.POLLIN)

        if poller.poll(timeout):
            response = socket.recv()
            mmb_dict = json.loads(response.decode())[0]
            if 'confidence' in mmb_dict:
                self.metadata['confidence'] = mmb_dict['confidence']
            if 'prediction' in mmb_dict:
                self.metadata['prediction'] = mmb_dict['prediction']
            if 'function_names' in mmb_dict:
                self.metadata['functionNames'] = mmb_dict['function_names']
            if 'vba_lang_features' in mmb_dict:
                self.metadata['langFeatures'] = mmb_dict['vba_lang_features']
            if 'vba_avg_param_per_func' in mmb_dict:
                self.metadata['avgParamPerFunc'] = mmb_dict['vba_avg_param_per_func']
            if 'vba_cnt_comment_loc_ratio' in mmb_dict:
                self.metadata['cntCommentLocRatio'] = mmb_dict['vba_cnt_comment_loc_ratio']
            if 'vba_cnt_comments' in mmb_dict:
                self.metadata['cntComments'] = mmb_dict['vba_cnt_comments']
            if 'vba_cnt_func_loc_ratio' in mmb_dict:
                self.metadata['cntFunctionLocRatio'] = mmb_dict['vba_cnt_func_loc_ratio']
            if 'vba_cnt_functions' in mmb_dict:
                self.metadata['cntFunctions'] = mmb_dict['vba_cnt_functions']
            if 'vba_cnt_loc' in mmb_dict:
                self.metadata['cntLoc'] = mmb_dict['vba_cnt_loc']
            if 'vba_entropy_chars' in mmb_dict:
                self.metadata['entropyChars'] = mmb_dict['vba_entropy_chars']
            if 'vba_entropy_func_names' in mmb_dict:
                self.metadata['entropyFuncNames'] = mmb_dict['vba_entropy_func_names']
            if 'vba_entropy_words' in mmb_dict:
                self.metadata['entropyWords'] = mmb_dict['vba_entropy_words']
            if 'vba_mean_loc_per_func' in mmb_dict:
                self.metadata['meanLocPerFunc'] = mmb_dict['vba_mean_loc_per_func']
        else:
            file_object.flags.append(f'{self.scanner_name}::zmq_timeout')

        socket.close()
        context.term()
