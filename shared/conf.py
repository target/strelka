"""Defines functions that are used to parse configuration files."""
import os

import yaml

scan_cfg = {}
remote_cfg = {}


def parse_yaml(path, section):
    """Parses configuration files.

    This function parses configuration files and either stores their sections
    in memory or returns them. Some configuration sections are stored in memory
    so they can be accessed from any location.

    Args:
        path: Location of the configuration file.
        section: Section to parse from the configuration file.

    Returns:
        If the section is not stored in memory, then returns the parsed section
        from the configuration file.
    """
    yml = None
    with open(path) as fin:
        yml = yaml.load(fin.read())

    if yml is not None:
        if section == "remote":
            global remote_cfg
            for option in yml[section]:
                if option not in remote_cfg:
                    remote_cfg[option] = yml[section][option] or os.environ.get(option.upper())
        elif section == "scan":
            global scan_cfg
            for option in yml[section]:
                scan_cfg.setdefault(option, {})
                for sub_option in yml[section][option]:
                    scan_cfg[option][sub_option] = yml[section][option][sub_option]
        elif section in yml:
            config = {}
            for option in yml[section]:
                if isinstance(yml[section][option], dict):
                    config.setdefault(option, {})
                    for sub_option in yml[section][option]:
                        if sub_option not in config[option]:
                            config[option][sub_option] = yml[section][option][sub_option]
                else:
                    if option not in config:
                        config[option] = yml[section][option]
            return config
