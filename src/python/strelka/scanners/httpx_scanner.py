from strelka import strelka
import json
import mimetypes
import re
import subprocess
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from kafka import KafkaProducer
import base64
from datetime import datetime, timezone

# لو حابب في المستقبل تفعّل S3:
# هتفك الكومنت عن boto3 وعن upload_to_s3 تحت، وتزود s3_bucket في options
# import boto3


# --------------------------------------------------------------------------------------
# DEFAULT HTTPX ARGS
# --------------------------------------------------------------------------------------
# فيها -ss عشان يطلع screenshots
# إحنا مش بنكتب السكرين شوت على الديسك، بس بنقراها من المسار اللي httpx بيعمله
DEFAULT_HTTPX_ARGS = [
    "-sc",
    "-cl",
    "-ct",
    "-title",
    "-location",
    "-favicon",
    "-hash",
    "md5",
    "-rt",
    "-lc",
    "-wc",
    "-server",
    "-td",
    "-method",
    "-ip",
    "-cname",
    "-asn",
    "-cdn",
    "-probe",
    "-tls-grab",
    "-ss",  # screenshot
    "-fr",
    "-maxr",
    "10",
    "-include-chain",
    "-json",
    "-irh",
    "-irr",
    "-irrb",
    "-j",
]


# ================== HELPER FUNCTIONS ==================


def run_httpx(
    httpx_cmd: str,
    url: str,
    raw_output: Path,
    extra_args: Optional[List[str]] = None,
    work_dir: Optional[Path] = None,
) -> None:
    """
    يشغّل httpx CLI على URL معيّن
    ويخلّيه يكتب الـ output بتاعه في ملف JSONL (ده الـ *وحيد* اللي بيتكتب على الديسك عن طريق httpx نفسه).
    كود الاسكانر نفسه مش بيكتب أي فايلات.
    """
    args = [httpx_cmd, "-u", url, *(extra_args or []), "-o", str(raw_output)]
    cmd_str = " ".join(str(part) for part in args)
    print(f"[httpx] Running: {cmd_str}")
    subprocess.run(args, check=True, cwd=str(work_dir) if work_dir else None)


def read_last_record(raw_output: Path) -> Dict[str, Any]:
    """
    يقرأ ملف JSONL بتاع httpx
    ويرجع آخر سطر JSON مش فاضي (آخر record).
    ده *قراءة* بس من الديسك، مفيش كتابة.
    """
    if not raw_output.exists():
        raise FileNotFoundError(f"Raw httpx output not found: {raw_output}")
    last_line = None
    with raw_output.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                last_line = stripped
    if not last_line:
        raise ValueError(f"No JSON lines found in {raw_output}")
    return json.loads(last_line)


def sanitize_name(value: str, fallback: str = "artifact") -> str:
    """
    ينضّف string عشان ينفع يبقى اسم فايل / host:
    - يشيل أي character غريب ويبدله بـ "_"
    """
    if not value:
        return fallback
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return safe or fallback


def normalize_external_path(raw_path: str, base_dir: Optional[Path] = None) -> Optional[Path]:
    """
    يحاول يحوّل مسار جاي من httpx لمسار فعلي على النظام:
    - لو relative + عندنا base_dir → نجرب نركّبه
    - لو absolute وموجود → نرجّعه
    - يحاول يحوّل مسارات WSL من /mnt/c/... → C:\\...
    (كل ده استخدام *قراءة* بس، مش هنخلق ملفات جديدة)
    """
    path = Path(raw_path)
    if not path.is_absolute() and base_dir is not None:
        candidate = (base_dir / path).resolve()
        if candidate.exists():
            return candidate
    if path.exists():
        return path
    raw_str = str(raw_path)
    if raw_str.startswith("/mnt/") and len(raw_str) > 6:
        drive_letter = raw_str[5]
        rest = raw_str[7:] if raw_str[6] == "/" else raw_str[6:]
        windows_rest = rest.replace("/", "\\")
        candidate = Path(f"{drive_letter.upper()}:\\{windows_rest}")
        if candidate.exists():
            return candidate
    return None


def infer_content_type(record: Dict[str, Any]) -> str:
    """
    يستنتج الـ Content-Type من record:
    - من record["content_type"]
    - أو من header["content-type"]
    """
    content_type = (record.get("content_type") or "").lower()
    if not content_type:
        header = record.get("header") or {}
        content_type = (header.get("content-type") or header.get("content_type") or "").lower()
    return content_type


def should_process_body(record: Dict[str, Any]) -> bool:
    """
    يقرر هل نعالج body ولا لأ (in-memory):
    - لو مفيش content-type → لا
    - لو HTML → لا
    - أي حاجة تانية (PDF/ZIP/EXE/JSON/Image...) → أيوة
    """
    content_type = infer_content_type(record)
    if not content_type:
        return False
    html_tokens = ("text/html", "application/xhtml")
    return not any(token in content_type for token in html_tokens)


def strip_http_headers(payload: bytes) -> bytes:
    """
    يشيل HTTP headers من response raw:
    لو فيه "HTTP/1.1 ...\\r\\n\\r\\n<body>" يرجع body بس.
    كل ده in-memory.
    """
    if not payload:
        return payload
    body = payload
    for _ in range(5):  # عشان لو فيه nested responses
        for marker in (b"\r\n\r\n", b"\n\n"):
            idx = body.find(marker)
            if idx != -1:
                potential = body[idx + len(marker):]
                if potential.startswith(b"HTTP/"):
                    # ده غالباً nested response، نكمّل لفة تانية
                    body = potential
                    break
                # ده البودي الحقيقي
                return potential
        else:
            break
    return body


def extension_from_content_type(content_type: str) -> str:
    """
    يحدد امتداد الفايل من الـ Content-Type.
    - لو معرفناش → .bin
    - لو text/* → .subtype أو .txt
    """
    if not content_type:
        return ".bin"
    mime = content_type.split(";", 1)[0].strip()
    guessed = mimetypes.guess_extension(mime)
    if guessed:
        return guessed
    if mime.startswith("text/"):
        subtype = mime.split("/", 1)[1] if "/" in mime else ""
        return f".{subtype or 'txt'}"
    return ".bin"


def extract_body_bytes(record: Dict[str, Any], base_dir: Optional[Path]) -> Optional[bytes]:
    """
    يطلع البودي كـ bytes *من غير ما يكتب أي حاجة على الديسك*:

    - لو فيه stored_response_path → نقرى الفايل ده بس ون strip headers
    - لو فيه body في JSON → نستخدمه
    """
    if not should_process_body(record):
        return None

    stored_path = record.get("stored_response_path")
    if stored_path:
        source = normalize_external_path(stored_path, base_dir=base_dir)
        if source and source.exists():
            data = source.read_bytes()       # قراءة بس
            return strip_http_headers(data)

    body = record.get("body")
    if body is None:
        return None

    if isinstance(body, bytes):
        return strip_http_headers(body)
    else:
        return strip_http_headers(body.encode("utf-8", errors="replace"))


def resolve_screenshot_bytes(record: Dict[str, Any], base_dir: Optional[Path]) -> Optional[bytes]:
    """
    يقرأ screenshot bytes لو httpx طلع سكرين شوت:
    - نستخدم المسار اللي httpx كتبه (screenshot_path / screenshot_path_rel)
    - نقرأ الفايل كـ bytes
    - مفيش أي كتابة للديسك هنا.
    """
    screenshot_path = record.get("screenshot_path") or record.get("screenshot_path_rel")
    if not screenshot_path:
        return None
    source = normalize_external_path(screenshot_path, base_dir=base_dir)
    if source and source.exists():
        return source.read_bytes()  # قراءة بس
    return None


def build_certificates(tls_info: Optional[Dict[str, Any]]) -> List[Dict[str, Optional[str]]]:
    """
    يجهّز قائمة بالشهادات من tls_info (واحدة بس في ليست).
    """
    if not tls_info:
        return []
    return [
        {
            "subject": tls_info.get("subject_dn") or tls_info.get("subject_cn"),
            "issuer": tls_info.get("issuer_dn") or tls_info.get("issuer_cn"),
            "validFrom": tls_info.get("not_before"),
            "validTo": tls_info.get("not_after"),
            "serialNumber": tls_info.get("serial"),
        }
    ]


def extract_page_info(record: Dict[str, Any], tls_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    يطلع معلومات عامة عن الـ target:
    - url
    - domain
    - ip
    - asn / asnname / ptr
    - server
    - tls issuer / validFrom / validTo
    - title
    """
    parsed_url = urlparse(record.get("url") or record.get("final_url") or "")
    host = record.get("host") or parsed_url.netloc
    ip = record.get("ip")
    if not ip:
        ipv4 = (record.get("a") or [])
        if ipv4:
            ip = ipv4[0]
    header = record.get("header") or {}
    server = (
        header.get("server")
        or header.get("Server")
        or record.get("server")
        or record.get("tech")
    )
    return {
        "url": record.get("url"),
        "domain": host,
        "ip": ip,
        "asn": record.get("asn"),
        "asnname": record.get("asnname"),
        "ptr": record.get("ptr"),
        "server": server,
        "tlsIssuer": (tls_info or {}).get("issuer_cn") or (tls_info or {}).get("issuer_dn"),
        "tlsValidFrom": (tls_info or {}).get("not_before"),
        "tlsValidTo": (tls_info or {}).get("not_after"),
        "title": record.get("title"),
    }


def extract_redirects(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    يلمّ الـ redirect chain في شكل:
    - redirects: قائمة بسيطة (from, to, httpCode)
    - redirect_chain_details: الداتا الكاملة لكل hop
    """
    redirects: List[Dict[str, Any]] = []
    redirect_details: List[Dict[str, Any]] = []
    for hop in record.get("chain") or []:
        if not isinstance(hop, dict):
            continue
        from_url = hop.get("request-url") or hop.get("request_url")
        to_url = hop.get("location")
        http_code = hop.get("status_code")
        if from_url or to_url or http_code:
            redirects.append({"from": from_url, "to": to_url, "httpCode": http_code})
        redirect_details.append(
            {
                "request": hop.get("request"),
                "response": hop.get("response"),
                "status_code": hop.get("status_code"),
                "location": hop.get("location"),
                "request_url": from_url,
            }
        )
    return {"redirects": redirects, "redirect_chain_details": redirect_details}


def transform_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    بيجمع الـ TLS + page info + redirects في JSON واحد مرتب.
    """
    tls_info = record.get("tls")
    result = {
        "certificates": build_certificates(tls_info),
        "page": extract_page_info(record, tls_info),
        "final_url": record.get("final_url"),
        "status_code": record.get("status_code"),
    }
    result.update(extract_redirects(record))
    return result


def create_run_directory(base_dir: str = "httpx_tmp") -> Path:
    """
    يعمل فولدر جديد لكل run باسم:
    base_dir/run_YYYYMMDD_HHMMSS_micro

    ده *المكان الوحيد* في كودنا اللي بيعمل mkdir،
    وده بس عشان httpx نفسه يعرف يكتب الـ output بتاعه والـ screenshots.
    إحنا مش بنكتب أي فايل جوّا الفولدر ده بإيدينا.
    """
    root = Path(base_dir)
    root.mkdir(parents=True, exist_ok=True)
    run_dir = root / datetime.now().strftime("run_%Y%m%d_%H%M%S_%f")
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir.resolve()



class HttpxScanner(strelka.Scanner):
    """
    Scanner لـ Strelka:
    - يستقبل فايل txt فيه URL في أول سطر
    - يشغّل httpx على الـ URL
    - يقرأ JSONL output (من غير ما يخلق فايلات جديدة)
    - يطلع:
        * page info
        * TLS info
        * redirects
        * body bytes (لو مش HTML) → hash + emit_file
        * screenshot bytes (لو موجودة) → hash + emit_file
    - يحط التحليل في self.event["httpx"]
    - يحط IOCs في self.iocs
    """

    def _extract_iocs(self, url: str, record: Dict[str, Any], transformed: Dict[str, Any]):
        """
        يستخرج IOCs من:
        - input URL
        - final_url
        - redirects
        - domain
        - IPs
        - body hash (sha256)
        - screenshot hash (sha256)
        ويحطّها في self.iocs
        """
        # URL الأساسي
        if url:
            self.iocs.append({"type": "url", "value": url})

        # final_url
        final_url = transformed.get("final_url")
        if final_url:
            self.iocs.append({"type": "url", "value": final_url})

        # redirects
        for red in transformed.get("redirects", []):
            if red.get("from"):
                self.iocs.append({"type": "url", "value": red["from"]})
            if red.get("to"):
                self.iocs.append({"type": "url", "value": red["to"]})

        # domain
        page = transformed.get("page", {})
        domain = page.get("domain")
        if domain:
            self.iocs.append({"type": "domain", "value": domain})

        # IP الرئيسي
        ip = page.get("ip")
        if ip:
            self.iocs.append({"type": "ip", "value": ip})

        # A records
        if record.get("a"):
            for addr in record["a"]:
                self.iocs.append({"type": "ip", "value": addr})

        # file hash (لو اتحسب)
        sha256_body = transformed.get("downloaded_body_sha256")
        if sha256_body:
            self.iocs.append({"type": "hash", "subtype": "sha256", "value": sha256_body})

        # screenshot hash (لو موجود)
        sha256_shot = transformed.get("screenshot_sha256")
        if sha256_shot:
            self.iocs.append({"type": "hash", "subtype": "sha256", "value": sha256_shot})

    def _extract_url_from_text_file(self, data: bytes) -> Optional[str]:
        """
        يفك محتوى txt ويجيب أول سطر مش فاضي ويعتبره URL.
        """
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return None
        test = []
        for line in text.splitlines():
            test.append(line.strip())
        if len(test) > 0:
            return test 
        return None

    def scan(self, data, file, options, expire_at):
        """
        دي الدالة اللي Strelka بيناديها:
        - data: محتوى الفايل (txt فيه URL)
        - file: كائن File بتاع Strelka (metadata)
        - options: من ال backend config (httpx_cmd, run_base_dir, s3_bucket...)
        - expire_at: وقت انتهاء الـ job
        """
        # ✅ لازم httpx يبقى list (مش dict) طالما انت بتعمل append results
        if not isinstance(self.event.get("httpx"), list):
            self.event["httpx"] = []

        httpx_cmd = options.get("httpx_cmd", "httpx_tmp")
        run_base_dir = options.get("run_base_dir", "/tmp/httpx_tmp")

        # نطلّع الـ URLs من محتوى الـ txt
        urls = self._extract_url_from_text_file(data) or []
        print(len(urls))

        # ✅ جهّز uuid_part مرة واحدة عشان يبقى متاح للـ BODY والـ SCREENSHOT
        file_name = getattr(file, "name", "") or ""
        if "___" in file_name:
            uuid_part = file_name.split("___", 1)[0]
        else:
            uuid_part = "unknown"

        # ✅ Producer واحد خارج اللوب (أوفر + أحسن)
        ANALYSIS_TOPIC = "downloaded.files"
        producer = KafkaProducer(
            bootstrap_servers=options.get("kafka_bootstrap", "kafka:29092"),
            value_serializer=lambda x: json.dumps(x).encode("utf-8"),
            max_request_size=104857600,  # 100MB
        )

        for url in urls:
            transformed = {}
            run_dir = None

            try:
                run_dir = create_run_directory(run_base_dir)

                if not url:
                    url = getattr(file, "name", None)

                if not url:
                    self.flags.append("httpx_no_url")
                    continue

                transformed["input_url"] = url

                internal_output_rel = Path("httpx_output.jsonl")
                internal_output = run_dir / internal_output_rel

                run_httpx(httpx_cmd, url, internal_output_rel, DEFAULT_HTTPX_ARGS, run_dir)

                record = read_last_record(internal_output)

                safe_name = sanitize_name(record.get("host") or urlparse(url).netloc or "target")

                transformed.update(transform_record(record))
                transformed["raw_httpx_output"] = str(internal_output)
                transformed["httpx_run_directory"] = str(run_dir)

                # ========== BODY ==========
                body_bytes = extract_body_bytes(record, base_dir=run_dir)
                if body_bytes:
                    sha256_body = hashlib.sha256(body_bytes).hexdigest()
                    transformed["downloaded_body_sha256"] = sha256_body

                    content_type = infer_content_type(record)
                    ext = extension_from_content_type(content_type)
                    filename = f"{safe_name}{ext}"

                    self.emit_file(body_bytes, name=f"{uuid_part}___files")
                    transformed["downloaded_body_emitted"] = True
                    transformed["downloaded_body_filename"] = filename

                    payload = {
                        "mid": uuid_part,
                        "@timestamp": datetime.now(timezone.utc)
                            .isoformat(timespec="microseconds")
                            .replace("+00:00", "Z"),
                        "ingest_meta": {
                            "source": "smtpsensor",
                            "journal_mailbox": "unknown",
                        },
                        "raw": base64.b64encode(body_bytes).decode("utf-8"),
                    }

                    try:
                        producer.send(ANALYSIS_TOPIC, value=payload)
                        producer.flush(1)
                        print(f"[KAFKA] Sent BODY JSON for {uuid_part}")
                    except Exception as e:
                        print("KAFKA error (body):", e)

                # ========== SCREENSHOT ==========
                shot_bytes = resolve_screenshot_bytes(record, base_dir=run_dir)
                if shot_bytes:
                    sha256_shot = hashlib.sha256(shot_bytes).hexdigest()
                    transformed["screenshot_sha256"] = sha256_shot

                    suffix = ".png"
                    screenshot_path = record.get("screenshot_path") or record.get("screenshot_path_rel")
                    if isinstance(screenshot_path, str):
                        p = Path(screenshot_path)
                        if p.suffix:
                            suffix = p.suffix

                    shot_name = f"{safe_name}_screenshot{suffix}"
                    transformed["screenshot_emitted"] = True
                    transformed["screenshot_filename"] = shot_name

                    payload = {
                        "mid": uuid_part,
                        "@timestamp": datetime.now(timezone.utc)
                            .isoformat(timespec="microseconds")
                            .replace("+00:00", "Z"),
                        "ingest_meta": {
                            "source": "screenshot",
                            "journal_mailbox": "unknown",
                        },
                        "raw": base64.b64encode(shot_bytes).decode("utf-8"),
                    }

                    try:
                        producer.send(ANALYSIS_TOPIC, value=payload)
                        producer.flush(1)
                        print(f"[KAFKA] Sent SCREENSHOT JSON for {uuid_part}")
                    except Exception as e:
                        print("KAFKA error (screenshot):", e)

                # سجل النتيجة
                self.event["httpx"].append(transformed)

            except Exception as exc:
                self.flags.append("httpx_error")

                # ✅ سجل الخطأ بشكل آمن لأن httpx عندنا list
                self.event.setdefault("errors", [])
                self.event["errors"].append({
                    "scanner": "httpx",
                    "mid": uuid_part,
                    "url": url,
                    "error": str(exc),
                })
            finally:
                # قفل producer مش هنا عشان مستخدمينه لباقي URLs
                # تنظيف run_dir لو عندك cleanup function (اختياري)
                pass
