"""Defines functions that are used to distribute files and manage scanners."""
import logging
import re

import inflection
import interruptingcow

from server import objects
from shared import conf
from shared import errors

scanner_cache = {}


def distribute(file_object, scan_result):
    """Distributes a file through scanners.

    Defines the primary method through which files are assigned scanners:
    file data is tasted and flavors are identified, file objects are mapped to
    scanners in the scan configuration, and scanners are run against the file.
    This function is recursively called if the file creates child files.

    Args:
        file_object: StrelkaFile instance that needs to be scanned.
        scan_result: Dictionary that scan results are appended to.
    """
    distro_cfg = conf.scan_cfg.get("distribution", {})
    scanner_cfg = conf.scan_cfg.get("scanners", [])
    merged_flavors = (file_object.flavors["external"] +
                      file_object.flavors["mime"] +
                      file_object.flavors["yara"])
    scanner_list = []
    for scanner_name in scanner_cfg:
        scanner_mappings = scanner_cfg.get(scanner_name, {})
        assigned_scanner = assign_scanner(scanner_name,
                                          scanner_mappings,
                                          merged_flavors,
                                          file_object.filename,
                                          file_object.source)
        if assigned_scanner is not None:
            scanner_list.append(assigned_scanner)
            file_object.scanner_list.append(scanner_name)

    scanner_list.sort(key=lambda k: k.get("priority", 5), reverse=True)
    maximum_depth = distro_cfg.get("maximum_depth", 15)
    if file_object.depth <= maximum_depth:
        children = []

        try:
            distribution_timeout = distro_cfg.get("distribution_timeout",
                                                  1800)
            with interruptingcow.timeout(distribution_timeout,
                                         exception=errors.DistributionTimeout):
                for scanner in scanner_list:
                    try:
                        scanner_name = scanner["scanner_name"]
                        und_scanner_name = inflection.underscore(scanner_name)
                        scanner_import = f"server.scanners.{und_scanner_name}"
                        module = __import__(scanner_import,
                                            fromlist=[und_scanner_name])
                        if und_scanner_name not in scanner_cache:
                            if hasattr(module, scanner_name):
                                scanner_cache[und_scanner_name] = getattr(module,
                                                                          scanner_name)()
                        scanner_options = scanner.get("options", {})
                        scanner_plugin = scanner_cache[und_scanner_name]
                        file_children = scanner_plugin.scan_wrapper(file_object,
                                                                    scanner_options)
                        children.extend(file_children)

                    except ModuleNotFoundError:
                        logging.exception(f"scanner {scanner_name} not found")

                unique_flags = list(dict.fromkeys(file_object.flags))
                result_output = {"flags": objects.ensure_utf8(unique_flags),
                                 "flavors": file_object.flavors,
                                 **file_object.metadata}
                scan_result["results"].append(result_output)

        except errors.DistributionTimeout:
            logging.exception(f"file with hash {file_object.hash} (uid"
                              f" {file_object.uid}) timed out")

        for child in children:
            distribute(child, scan_result)

    else:
        logging.info(f"file with hash {file_object.hash} (root hash"
                     f" {file_object.root_hash}) exceeded maximum depth")


def assign_scanner(scanner, mappings, flavors, filename, source):
    """Assigns scanners based on mappings and file data.

    Performs the task of assigning scanners based on the scan configuration
    mappings and file flavors, filename, and source. Assignment supports
    positive and negative matching: scanners are assigned if any positive
    categories are matched and no negative categories are matched. Flavors are
    literal matches, filename and source matches uses regular expressions.

    Args:
        scanner: Name of the scanner being assigned.
        mappings: List of dictionaries that contain values used to assign
            the scanner to the file.
        flavors: List of file flavors to use during scanner assignment.
        filename: Filename to use during scanner assignment.
        source: File source to use during scanner assignment.

    Returns:
        A dictionary containing the assigned scanner or None.
    """
    for mapping in mappings:
        negatives = mapping.get("negative", {})
        positives = mapping.get("positive", {})
        neg_flavors = negatives.get("flavors", [])
        neg_filename = negatives.get("filename", None)
        neg_source = negatives.get("source", None)
        pos_flavors = positives.get("flavors", [])
        pos_filename = positives.get("filename", None)
        pos_source = positives.get("source", None)
        assigned_scanner = {"scanner_name": scanner,
                            "priority": mapping.get("priority", 5),
                            "options": mapping.get("options", {})}

        for neg_flavor in neg_flavors:
            if neg_flavor in flavors:
                return None
        if neg_filename is not None:
            if re.search(neg_filename, filename) is not None:
                return None
        if neg_source is not None:
            if re.search(neg_source, source) is not None:
                return None
        for pos_flavor in pos_flavors:
            if pos_flavor == "*" or pos_flavor in flavors:
                return assigned_scanner
        if pos_filename is not None:
            if re.search(pos_filename, filename) is not None:
                return assigned_scanner
        if pos_source is not None:
            if re.search(pos_source, source) is not None:
                return assigned_scanner
    return None


def close_scanners():
    """Runs the close wrapper method on open scanners."""
    for (scanner_name, scanner_pointer) in list(scanner_cache.items()):
        scanner_pointer.close_wrapper()
        logging.debug(f"closed scanner {inflection.camelize(scanner_name)}")
