import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from strelka import strelka


class ScanPcap(strelka.Scanner):
    """Extract files from pcap/pcapng files, use Suricata to match alert signatures.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """

    def scan(
        self, data: bytes, file: Dict[str, Any], options: Dict[str, Any], expire_at: int
    ) -> None:
        """Process pcap/pcapng data and extract files using Zeek and optionally run Suricata.

        Args:
            data: Raw pcap/pcapng data.
            file: File metadata.
            options: Scanner options.
            expire_at: Expiration timestamp.
        """
        self.expire_at = expire_at
        self.file_limit: int = options.get("limit", 1000)
        self.tmp_directory: str = options.get("tmp_file_directory", "/tmp/")
        self.zeek_conn: Optional[bool] = options.get("zeek_conn", True)
        self.zeek_conn_limit: Optional[int] = options.get("zeek_conn_limit", 100)
        self.zeek_proto: Optional[bool] = options.get("zeek_proto", True)
        self.suricata_config: Optional[str] = options.get("suricata_config", None)
        self.suricata_rules: Optional[str] = options.get("suricata_rules", None)
        self.suricata_alert_dedupe: bool = options.get("suricata_alert_dedupe", False)
        self.scanner_timeout: int = options.get("scanner_timeout", 120)

        self.event["total"] = {"files": 0, "extracted": 0}
        self.event["files"] = []

        try:
            # Check if zeek package is installed
            if not shutil.which("zeek"):
                self.flags.append("zeek_not_installed_error")
                return
        except Exception as e:
            self.flags.append(str(e))
            return

        with tempfile.NamedTemporaryFile(dir=self.tmp_directory, mode="wb") as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()
            tmp_data.seek(0)

            self.zeek_extract(tmp_data.name)

            if self.suricata_rules:
                try:
                    # Check if suricata package is installed
                    if not shutil.which("suricata"):
                        self.flags.append("suricata_not_installed_error")
                        return

                    self.suricata(tmp_data.name)
                except Exception as e:
                    self.flags.append(str(e))

    def zeek_extract(self, pcap_path: str) -> None:
        """Extract files from pcap using Zeek.

        Args:
            pcap_path: Path to the pcap file.
        """
        with tempfile.TemporaryDirectory() as tmp_zeek:
            try:

                # Zeek outputs to the current working directory by default
                os.chdir(tmp_zeek)

                stdout, stderr = subprocess.Popen(
                    [
                        "zeek",
                        "-r",
                        pcap_path,
                        "/opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek",
                        f"FileExtract::prefix={os.path.join(tmp_zeek, 'files')}",
                        "LogAscii::use_json=T",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate(timeout=self.scanner_timeout)

                files_log_path = os.path.join(tmp_zeek, "files.log")

                if os.path.exists(files_log_path):
                    self._process_files_log(
                        files_log_path, os.path.join(tmp_zeek, "files")
                    )
                else:
                    self.flags.append("zeek_no_file_log")

                if self.zeek_conn:
                    # Parse the conn.log file to get basic connection information
                    connections = []
                    total_connections = 0
                    conn_log = os.path.join(tmp_zeek, "conn.log")

                    if os.path.exists(conn_log):
                        with open(conn_log, "r") as f:
                            for line in f:
                                if line.startswith("#"):
                                    continue

                                total_connections += 1

                                if (
                                    self.zeek_conn_limit > 0
                                    and len(connections) >= self.zeek_conn_limit
                                ):
                                    if "zeek_conn_limit_reached" not in self.flags:
                                        self.flags.append("zeek_conn_limit_reached")
                                    continue

                                try:
                                    conn_data = json.loads(line)
                                    connection = {
                                        "uid": conn_data.get("uid"),
                                        "source_ip": conn_data.get("id.orig_h"),
                                        "source_port": conn_data.get("id.orig_p"),
                                        "dest_ip": conn_data.get("id.resp_h"),
                                        "dest_port": conn_data.get("id.resp_p"),
                                        "protocol": conn_data.get("proto"),
                                        "service": conn_data.get("service"),
                                        "duration": conn_data.get("duration"),
                                        "bytes_orig": conn_data.get("orig_bytes"),
                                        "bytes_resp": conn_data.get("resp_bytes"),
                                        "conn_state": conn_data.get("conn_state"),
                                    }

                                    connections.append(connection)
                                except json.JSONDecodeError:
                                    continue

                    if self.zeek_proto:
                        # Check for protocol-specific logs to enhance connection details
                        protocol_logs = [
                            "http.log",
                            "dns.log",
                            "ssl.log",
                            "ssh.log",
                            "smtp.log",
                            "ftp.log",
                            "rdp.log",
                            "sip.log",
                            "smb_mapping.log",
                        ]

                        # Map to store protocol details by connection UID
                        protocol_details = defaultdict(dict)

                        for log_name in protocol_logs:
                            log_path = os.path.join(tmp_zeek, log_name)
                            if os.path.exists(log_path):
                                protocol = log_name.split(".")[0]

                                with open(log_path, "r") as f:
                                    for line in f:
                                        if line.startswith("#"):
                                            continue
                                        try:
                                            log_data = json.loads(line)
                                            uid = log_data.get("uid")
                                            if uid:
                                                # Extract relevant details based on protocol
                                                if protocol == "http":
                                                    protocol_details[uid][protocol] = {
                                                        "method": log_data.get(
                                                            "method"
                                                        ),
                                                        "host": log_data.get("host"),
                                                        "uri": log_data.get("uri"),
                                                        "user_agent": log_data.get(
                                                            "user_agent"
                                                        ),
                                                        "status_code": log_data.get(
                                                            "status_code"
                                                        ),
                                                    }
                                                elif protocol == "dns":
                                                    protocol_details[uid][protocol] = {
                                                        "query": log_data.get("query"),
                                                        "qtype": log_data.get(
                                                            "qtype_name"
                                                        ),
                                                        "answers": log_data.get(
                                                            "answers"
                                                        ),
                                                    }
                                                elif protocol == "ssl":
                                                    protocol_details[uid][protocol] = {
                                                        "server_name": log_data.get(
                                                            "server_name"
                                                        ),
                                                        "subject": log_data.get(
                                                            "subject"
                                                        ),
                                                        "issuer": log_data.get(
                                                            "issuer"
                                                        ),
                                                        "version": log_data.get(
                                                            "version"
                                                        ),
                                                    }
                                                else:
                                                    # Generic extraction for other protocols
                                                    protocol_details[uid][protocol] = {
                                                        k: v
                                                        for k, v in log_data.items()
                                                        if k != "uid" and v is not None
                                                    }
                                        except json.JSONDecodeError:
                                            continue

                        # Merge protocol details with the basic connection information
                        for connection in connections:
                            uid = connection.get("uid")
                            if uid in protocol_details:
                                connection["protocol_details"] = protocol_details[uid]

                    self.event["total"]["connections"] = total_connections
                    self.event["connections"] = connections

            except strelka.ScannerTimeout:
                raise
            except Exception:
                self.flags.append("zeek_extract_process_error")
                raise

    def _process_files_log(self, log_path: str, extract_dir: str) -> None:
        """Process Zeek's files.log and upload extracted files.

        Args:
            log_path: Path to the files.log file.
            extract_dir: Directory where extracted files are stored.
        """
        try:
            with open(log_path, "r") as json_file:
                # files.log is one JSON object per line, convert to array
                file_events = json.loads(
                    "[" + ",".join(json_file.read().splitlines()) + "]"
                )

                for file_event in file_events:
                    if self.event["total"]["extracted"] >= self.file_limit:
                        self.flags.append("pcap_file_limit_error")
                        break

                    self.event["total"]["files"] += 1
                    self.event["files"].append(file_event)

                    extracted_file_path = os.path.join(
                        extract_dir, file_event["extracted"]
                    )

                    try:
                        if os.path.exists(extracted_file_path):
                            self.upload(extracted_file_path, self.expire_at)
                            self.event["total"]["extracted"] += 1
                    except strelka.ScannerTimeout:
                        raise
                    except Exception:
                        self.flags.append("zeek_file_upload_error")
        except Exception:
            self.flags.append("zeek_file_log_parse_error")

    def suricata(self, pcap_file: str) -> None:
        """Run Suricata on pcap file to generate alerts.

        Args:
            pcap_file: Path to the pcap file.
        """
        self.event["suricata"] = {}

        with tempfile.TemporaryDirectory() as tmp_suricata:
            try:
                self._scan_with_suricata(pcap_file, log_dir=tmp_suricata)

                # Paths to log files
                eve_log_file = os.path.join(tmp_suricata, "eve.json")
                suricata_log_file = os.path.join(tmp_suricata, "suricata.log")

                # Get matching alerts
                if os.path.exists(eve_log_file):
                    alerts = self._get_matching_alerts(eve_log_file)
                else:
                    alerts = []

                if len(alerts) == 0:
                    self.flags.append("suricata_no_alerts")

                if self.suricata_alert_dedupe:
                    alerts = self._deduplicate_alerts(alerts)

                self.event["suricata"]["alerts"] = alerts

                # Parse Suricata log file for additional statistics
                if os.path.exists(suricata_log_file):
                    self._parse_suricata_log(suricata_log_file)

            except strelka.ScannerTimeout:
                raise
            except Exception:
                self.flags.append("suricata_error")
                raise

    def _parse_suricata_log(self, log_file: str) -> None:
        """Parse Suricata log file to extract statistics.

        Extracts information about rules loaded and pcap processing stats.

        Args:
            log_file: Path to the Suricata log file.
        """
        try:
            with open(log_file, "r") as file:
                log_content = file.read()

                # Extract rule loading statistics
                rule_pattern = r"<Info> - (\d+) rule files processed\. (\d+) rules successfully loaded, (\d+) rules failed"
                rule_match = re.search(rule_pattern, log_content)

                if rule_match:
                    self.event["suricata"]["rules_stats"] = {
                        "rules_loaded": int(rule_match.group(2)),
                        "rules_failed": int(rule_match.group(3)),
                    }

                # Extract pcap processing statistics
                pcap_pattern = r"<Notice> - Pcap-file module read (\d+) files, (\d+) packets, (\d+) bytes"
                pcap_match = re.search(pcap_pattern, log_content)

                if pcap_match:
                    self.event["suricata"]["pcap_stats"] = {
                        "packets_read": int(pcap_match.group(2)),
                        "bytes_read": int(pcap_match.group(3)),
                    }

        except Exception:
            self.flags.append("suricata_log_parse_error")
            raise

    def _reload_rules(self, suricata_socket):
        """
        Runs the suricata process to refresh rules, as needed.

        Args:
            suricata_socket: location of the cutom suricata socket, as set in the suricata.yaml file
        """
        subprocess.run(
            f"suricata -c /etc/suricata/suricata.yaml --unix-socket -D -S {self.suricata_rules}",
            shell=True,
        )
        subprocess.Popen(
            ["suricatasc", "-c", "ruleset-reload-nonblocking", suricata_socket],
            stdout=subprocess.PIPE,
        ).communicate()[0]

    def _get_remaining_suricata(self, suricata_socket):
        """
        Retrieves the remaining information from the suricatasc process call

        Args:
            suricata_socket: location of the cutom suricata socket, as set in the suricata.yaml file
        """
        r = subprocess.Popen(
            ["suricatasc", "-c", "pcap-file-number", suricata_socket],
            stdout=subprocess.PIPE,
        ).communicate()[0]
        return int(json.loads(r.decode())["message"])

    def _scan_with_suricata(self, file_path: str, log_dir: str) -> None:
        """Run Suricata on the pcap file.

        Args:
            file_path: Path to the pcap file.
            log_dir: Directory to store Suricata logs.
        """
        suricata_socket = "/tmp/suricata-command.socket"

        result = subprocess.run(
            "suricata -c /etc/suricata/suricata.yaml --unix-socket -D",
            shell=True,
        )

        # Add custom rules if provided
        if self.suricata_rules:
            self._reload_rules(suricata_socket)

        # Run Suricata
        result = subprocess.run(
            f"suricatasc -c 'pcap-file {file_path} {log_dir} 0 true' {suricata_socket} ",
            shell=True,
        )
        print(result)
        while self._get_remaining_suricata(suricata_socket):  # wait for pcap to process
            time.sleep(0.05)

        if result.returncode != 0:
            self.flags.append("suricata_process_error")

    def _get_matching_alerts(self, log_file: str) -> List[Dict[str, Any]]:
        """Parse Suricata log file and extract alerts.

        Args:
            log_file: Path to the Suricata log file.

        Returns:
            List of alert dictionaries.
        """
        matching_alerts: List[Dict[str, Any]] = []
        with open(log_file, "r") as file:
            for line in file:
                log_entry = json.loads(line)
                if log_entry.get("event_type") == "alert":
                    matching_alerts.append(log_entry)
        return matching_alerts

    def _deduplicate_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate alerts based on signature ID.

        Args:
            alerts: List of alert dictionaries.

        Returns:
            Deduplicated list of alert dictionaries.
        """
        deduplicated_alerts: List[Dict[str, Any]] = []
        seen_signature_ids: Set[int] = set()
        for alert in alerts:
            signature_id = alert["alert"]["signature_id"]
            if signature_id not in seen_signature_ids:
                deduplicated_alerts.append(alert)
                seen_signature_ids.add(signature_id)
        return deduplicated_alerts

    def upload(self, name: str, expire_at: int) -> None:
        """Send extracted file to coordinator.

        Args:
            name: Path to the file to upload.
            expire_at: Expiration timestamp.
        """
        with open(name, "rb") as extracted_file:
            # Send extracted file back to Strelka
            self.emit_file(extracted_file.read())
