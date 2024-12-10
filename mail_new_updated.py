import hashlib
from aiosmtpd.controller import Controller
import logging
import os
import dns.resolver
from aiosmtpd.handlers import AsyncMessage
from datetime import datetime
from urllib.parse import urlparse
import re
import json
import logging

import apis

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("EmailHandler")

EMAIL_DIR = "emails"
SPAM_KEYWORDS = ["win", "money", "free", "urgent"]
DANGEROUS_EXTENSIONS = [".exe", ".bat", ".js"]
BLACKLISTED_DOMAINS = ["phishing.com", "malware.net"]
RBL_SERVERS = ["zen.spamhaus.org", "b.barracudacentral.org"]
os.makedirs(os.path.join(EMAIL_DIR, "inbox"), exist_ok=True)
os.makedirs(os.path.join(EMAIL_DIR, "spam"), exist_ok=True)
os.makedirs(os.path.join(EMAIL_DIR, "quarantine"), exist_ok=True)
os.makedirs(os.path.join(EMAIL_DIR, "sandbox"), exist_ok=True)

class EmailHandler(AsyncMessage):
    def __init__(self):
        super().__init__()
        self.report = {
            "total_emails": 0,
            "spam_detected": 0,
            "dangerous_attachments": 0,
            "blacklisted_links": 0,
            "sandboxed_emails": 0
        }

    async def handle_message(self, message):
        self.report["total_emails"] += 1
        email_subject = message.get("Subject", "(No Subject)")
        try:
            email_body = message.get_payload(decode=True).decode('utf-8', errors='replace')
        except AttributeError:
            email_body = "(No Body)"

        if self._contains_spam(email_body):
            self.report["spam_detected"] += 1
            self._save_email(email_body, "spam", email_subject)
            return

        if self._has_dangerous_attachments(message):
            self.report["dangerous_attachments"] += 1
            self._save_email(email_body, "quarantine", email_subject)
            return

        if self._has_blacklisted_or_malicious_links(email_body):
            self.report["blacklisted_links"] += 1
            self._save_email(email_body, "sandbox", email_subject)
            return

        self._save_email(email_body, "inbox", email_subject)

    def _contains_spam(self, body):
        return any(keyword in body.lower() for keyword in SPAM_KEYWORDS)
    
    def _scan_attachments_for_signatures(self, message):
        if not message.is_multipart():
            return False

        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                content = part.get_payload(decode=True)
                if content:
                    attachment_hash = hashlib.sha256(content).hexdigest()
                    hash_data = apis.check_hash_with_circl(attachment_hash)
                    if hash_data:
                        logger.warning(f"Niebezpieczny załącznik wykryty: {part.get_filename()} - {hash_data}")
                        return True
        return False

    def _has_dangerous_attachments(self, message):
        if not message.is_multipart():
            return False

        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                content = part.get_payload(decode=True)
                if content:
                    maliciousCount, totalReports, tScore = apis.fileCheck(content, filename)
                    if tScore > 0:
                        logger.warning(f"Niebezpieczny załącznik wykryty przez Hybrid Analysis: {filename}")
                        logger.warning(f"Threat Score: {tScore}")
                        logger.warning(f"{maliciousCount}/{totalReports} raportów oznaczonych jako *malicious*.")
                        return True
                    else:
                        logger.warning(f"Załącznik {filename} bezpieczny")
        return False

    def _has_blacklisted_or_malicious_links(self, body):
        urls = re.findall(r'http[s]?://\\S+', body)
        for url in urls:
            domain = urlparse(url).netloc
            if domain in BLACKLISTED_DOMAINS or self._check_rbl(domain):
                return True
        return False

    def _check_rbl(self, domain):
        try:
            for rbl in RBL_SERVERS:
                query = f"{domain}.{rbl}"
                dns.resolver.resolve(query, 'A')
                return True
        except dns.resolver.NXDOMAIN:
            return False
        except Exception as e:
            logger.warning(f"Error checking RBL for {domain}: {e}")
        return False

    def _save_email(self, content, folder, subject):
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        safe_subject = re.sub(r'[^a-zA-Z0-9_-]', '_', subject)[:50]
        filename = f"{timestamp}_{safe_subject}.txt"
        filepath = os.path.join(EMAIL_DIR, folder, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info(f"Email saved to {filepath}")

    def save_report(self):
        report_path = os.path.join(EMAIL_DIR, "report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(self.report, f, indent=4)

        logger.info(f"Report saved to {report_path}")


if __name__ == "__main__":
    handler = EmailHandler()
    controller = Controller(handler, hostname='127.0.0.1', port=1025)

    try:
        logger.info("Starting SMTP server...")
        controller.start()
        logger.info("SMTP server running. Press Ctrl+C to stop.")
        while True:
            pass
    except KeyboardInterrupt:
        logger.info("Stopping SMTP server...")
        controller.stop()
        handler.save_report()
