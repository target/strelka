# Strelka Python Client

## Prerequisites

1. Install requirements from `requirements.txt`
2. Copy `strelka_pb2_grpc.py` and `strelka_pb2.py` from `strelka/src/python/strelka/proto` into this directory

## Usage

This can be run from the command line using the same options as strelka-oneshot:

``` bash
python3 client.py -f filename.bin -s localhost:51314 -l output.log
```

Or it can be used as the `StrelkaFrontend` class:

``` python
from client import StrelkaFrontend
client = StrelkaFrontend(server="localhost:51314",gatekeeper=False)
result = client.ScanFile("filename.bin")
```
