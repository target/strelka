import os
import platform
from typing import Optional

from opentelemetry.sdk.resources import Resource

import strelka


def get_resource(meta: Optional[dict] = None):
    attributes = {
        "service.namespace": strelka.__namespace__,
        "service.name": "strelka.backend.worker",
        "service.version": strelka.__version__,
        "host.name": os.environ.get("HOSTNAME", None),
        "host.arch": platform.processor(),
        "os.type": platform.system(),
    }
    if meta:
        attributes.update(meta)

    return Resource(attributes=attributes)
