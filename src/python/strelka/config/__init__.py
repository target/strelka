import hashlib
import logging
import logging.config
import os

import yaml


class BackendConfig:
    def __init__(self, backend_cfg_path: str = "/etc/strelka/backend.yaml") -> None:
        self.dictionary: dict = {}

        if not os.path.exists(backend_cfg_path):
            raise Exception(f"backend configuration {backend_cfg_path} does not exist")

        try:
            with open(backend_cfg_path, "rb") as f:
                config_data = f.read()

                # Hash the config file, attach it to the config object
                h = hashlib.new("sha1")
                h.update(config_data)
                self.dictionary.update({"sha1": h.hexdigest()})

                # Parse yaml
                self.dictionary.update(yaml.safe_load(config_data))
        except yaml.YAMLError:
            logging.exception("backend configuration failed to parse")
            raise

        logging.info(f"loaded backend configuration from {backend_cfg_path}")

        self.configure_logging()

    def configure_logging(self):
        log_cfg_path = self.dictionary.get("logging_cfg")
        if os.path.exists(log_cfg_path):
            with open(log_cfg_path) as f:
                logging.config.dictConfig(yaml.safe_load(f.read()))
