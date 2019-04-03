import json

import grpc

from strelka import core
from strelka.proto import mmbot_pb2
from strelka.proto import mmbot_pb2_grpc


class ScanMmbot(core.StrelkaScanner):
    """Collects Visual Basic results from an mmprc service.

    Options:
        server: Network address and network port of the mmrpc service.
            Defaults to 127.0.0.1:33907.
    """
    def scan(self, st_file, options):
        server = options.get('server', '127.0.0.1:33907')

        with grpc.insecure_channel(server) as channel:
            stub = mmbot_pb2_grpc.MmbotStub(channel)
            response = stub.SendVba(mmbot_pb2.Vba(vba=self.data.decode()))

        mmb_dict = json.loads(response.prediction)
        self.metadata['confidence'] = mmb_dict.get('confidence', None)
        self.metadata['prediction'] = mmb_dict.get('prediction', None)
        self.metadata['functionNames'] = mmb_dict.get('function_names', None)
        self.metadata['langFeatures'] = mmb_dict.get('vba_lang_features', None)
        self.metadata['avgParamPerFunc'] = mmb_dict.get('vba_avg_param_per_func', None)
        self.metadata['cntCommentLocRatio'] = mmb_dict.get('vba_cnt_comment_loc_ratio', None)
        self.metadata['cntComments'] = mmb_dict.get('vba_cnt_comments', None)
        self.metadata['cntFunctionLocRatio'] = mmb_dict.get('vba_cnt_func_loc_ratio', None)
        self.metadata['cntFunctions'] = mmb_dict.get('vba_cnt_functions', None)
        self.metadata['cntLoc'] = mmb_dict.get('vba_cnt_loc', None)
        self.metadata['entropyChars'] = mmb_dict.get('vba_entropy_chars', None)
        self.metadata['entropyFuncNames'] = mmb_dict.get('vba_entropy_func_names', None)
        self.metadata['entropyWords'] = mmb_dict.get('vba_entropy_words', None)
        self.metadata['meanLocPerFunc'] = mmb_dict.get('vba_mean_loc_per_func', None)
