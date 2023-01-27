import json

import grpc
from strelka.proto import mmbot_pb2, mmbot_pb2_grpc

from strelka import strelka


class ScanMmbot(strelka.Scanner):
    """Collects Visual Basic results from an mmprc service.

    Options:
        server: Network address and network port of the mmrpc service.
            Defaults to strelka_mmrpc_1:33907.
    """

    def scan(self, data, file, options, expire_at):
        server = options.get("server", "strelka_mmrpc_1:33907")

        with grpc.insecure_channel(server) as channel:
            stub = mmbot_pb2_grpc.MmbotStub(channel)
            response = stub.SendVba(mmbot_pb2.Vba(vba=data.decode()))

        mmb_dict = json.loads(response.prediction)
        self.event["confidence"] = mmb_dict.get("confidence", None)
        self.event["prediction"] = mmb_dict.get("prediction", None)
        self.event["functions"] = mmb_dict.get("function_names", None)
        self.event["features"] = mmb_dict.get("vba_lang_features", None)
        self.event["total"] = {
            "comments": mmb_dict.get("vba_cnt_comments", None),
            "functions": mmb_dict.get("vba_cnt_functions", None),
            "locations": mmb_dict.get("vba_cnt_loc", None),
        }
        self.event["ratio"] = {
            "comments": mmb_dict.get("vba_cnt_comment_loc_ratio", None),
            "functions": mmb_dict.get("vba_cnt_func_loc_ratio", None),
        }
        self.event["entropy"] = {
            "characters": mmb_dict.get("vba_entropy_chars", None),
            "functions": mmb_dict.get("vba_entropy_func_names", None),
            "words": mmb_dict.get("vba_entropy_words", None),
        }
