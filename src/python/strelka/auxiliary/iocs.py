import re
from urllib.parse import urlparse

import tldextract


def extract_iocs_from_string(input_string):
    """
    Extracts various types of Indicators of Compromise (IOCs) from a string.
    This function looks for domain names and IP addresses within the given string.
    Args:
        input_string (str): The input string to search for IOCs.
    Returns:
        list: A list with iocs of unique extracted values.
    """
    iocs = set()
    iocs.update(extract_domains_from_string(input_string))
    iocs.update(extract_ip_addresses(input_string))
    return list(iocs)


def extract_domains_from_string(input_string):
    """
    Extracts domain names from a string containing URLs.
    Args:
        input_string (str): The input string to search for URLs.
    Returns:
        set: A set of unique domain names extracted from the URLs.
    """
    domains = set()

    # Use a regular expression to find URLs in the data string
    urls = re.findall(r"(?:https?|ftp|ftps|file|smb)://[^\s/$.?#].[^\s]*", input_string)

    for url in urls:
        # Use urlparse to check if the string is a valid URL
        parsed_url = urlparse(url)
        if parsed_url.scheme and parsed_url.netloc:
            # Use tldextract to extract the domain from the URL
            extracted = tldextract.extract(url)
            domain = (
                f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}".strip(
                    "."
                )
            )
            domains.add(domain)

    return list(domains)


def extract_ip_addresses(input_string):
    """
    Extracts IP addresses from a string.
    Args:
        input_string (str): The input string to search for IP addresses.
    Returns:
        list: A list of unique IP addresses extracted from the input string.
    """
    ip_addresses = set()

    # Regular expressions for matching IPv4 and IPv6 addresses
    ipv4_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    ipv6_pattern = r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b"

    # Find all matching IP addresses
    ipv4_addresses = re.findall(ipv4_pattern, input_string, re.IGNORECASE)
    ipv6_addresses = re.findall(ipv6_pattern, input_string, re.IGNORECASE)

    # Add found IP addresses to the set
    ip_addresses.update(ipv4_addresses)
    ip_addresses.update(ipv6_addresses)

    return list(ip_addresses)
