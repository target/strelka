import json

import grpc

from strelka import strelka
from strelka.proto import mmbot_pb2
from strelka.proto import mmbot_pb2_grpc


class ScanMmbot(strelka.Scanner):
    """Collects Visual Basic results from an mmprc service.

    Options:
        server: Network address and network port of the mmrpc service.
            Defaults to 127.0.0.1:33907.
    """
    def scan(self, data, file, options, expire_at):
        server = options.get('server', '127.0.0.1:33907')

        with grpc.insecure_channel(server) as channel:
            stub = mmbot_pb2_grpc.MmbotStub(channel)
            response = stub.SendVba(mmbot_pb2.Vba(vba=data.decode()))

        mmb_dict = json.loads(response.prediction)
        self.event['confidence'] = mmb_dict.get('confidence', None)
        self.event['prediction'] = mmb_dict.get('prediction', None)
        self.event['function_names'] = mmb_dict.get('function_names', None)
        self.event['lang_features'] = mmb_dict.get('vba_lang_features', None)
        self.event['avg_param_per_func'] = mmb_dict.get('vba_avg_param_per_func', None)
        self.event['cnt_comment_loc_ratio'] = mmb_dict.get('vba_cnt_comment_loc_ratio', None)
        self.event['cnt_comments'] = mmb_dict.get('vba_cnt_comments', None)
        self.event['cnt_function_loc_ratio'] = mmb_dict.get('vba_cnt_func_loc_ratio', None)
        self.event['cnt_functions'] = mmb_dict.get('vba_cnt_functions', None)
        self.event['cnt_loc'] = mmb_dict.get('vba_cnt_loc', None)
        self.event['entropy_chars'] = mmb_dict.get('vba_entropy_chars', None)
        self.event['entropy_func_names'] = mmb_dict.get('vba_entropy_func_names', None)
        self.event['entropy_words'] = mmb_dict.get('vba_entropy_words', None)
        self.event['mean_loc_per_func'] = mmb_dict.get('vba_mean_loc_per_func', None)
