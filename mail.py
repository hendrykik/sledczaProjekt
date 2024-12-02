import smtpd
import asyncore
import logging
import os
import re
import json
from datetime import datetime

# Konfiguracja loggera
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Foldery na różne rodzaje wiadomości
INBOX_FOLDER = "emails/inbox"
SPAM_FOLDER = "emails/spam"
QUARANTINE_FOLDER = "emails/quarantine"
REPORT_FILE = "emails/report.json"

os.makedirs(INBOX_FOLDER, exist_ok=True)
os.makedirs(SPAM_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

# Statystyki dla raportów
report_data = {
    "total_emails": 0,
    "spam_count": 0,
    "quarantined_count": 0,
    "dangerous_attachments": 0,
    "malicious_links": 0
}

class EmailProxyServer(smtpd.SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        logger.info(f'Received email from: {mailfrom}')
        logger.info(f'To: {rcpttos}')
        logger.info(f'Data:{data.decode("utf-8")}')

        # Analiza treści wiadomości
        is_spam, is_dangerous, analysis_results = self.analyze_email(mailfrom, rcpttos, data)

        # Decyzja: do kwarantanny, spamu czy inbox
        if is_dangerous:
            self.save_email(QUARANTINE_FOLDER, mailfrom, rcpttos, data, analysis_results)
            report_data["quarantined_count"] += 1
        elif is_spam:
            self.save_email(SPAM_FOLDER, mailfrom, rcpttos, data, analysis_results)
            report_data["spam_count"] += 1
        else:
            self.save_email(INBOX_FOLDER, mailfrom, rcpttos, data, analysis_results)

        # Zwiększ licznik wszystkich wiadomości
        report_data["total_emails"] += 1

        # Aktualizuj raport
        self.update_report()

    def analyze_email(self, mailfrom, rcpttos, data):
        """Analizuje wiadomość pod kątem spamu, załączników i odnośników."""
        is_spam = False
        is_dangerous = False
        analysis_results = {
            "spam": False,
            "dangerous_attachments": False,
            "malicious_links": False
        }

        message_content = data.decode("utf-8")

        # Prosta analiza treści (np. słowa kluczowe spamu)
        spam_keywords = ["win", "free money", "click here"]
        if any(keyword in message_content.lower() for keyword in spam_keywords):
            is_spam = True
            analysis_results["spam"] = True

        # Analiza załączników
        dangerous_extensions = [".exe", ".bat", ".js"]
        attachment_pattern = r"filename=\"(.*?)\""
        attachments = re.findall(attachment_pattern, message_content)
        if any(att.endswith(tuple(dangerous_extensions)) for att in attachments):
            is_dangerous = True
            analysis_results["dangerous_attachments"] = True
            report_data["dangerous_attachments"] += 1

        # Analiza linków (Threat Intelligence - przykładowa analiza RBL)
        link_pattern = r"https?://[\w.-]+"
        links = re.findall(link_pattern, message_content)
        for link in links:
            if self.is_malicious_link(link):
                is_dangerous = True
                analysis_results["malicious_links"] = True
                report_data["malicious_links"] += 1

        return is_spam, is_dangerous, analysis_results

    def is_malicious_link(self, link):
        """Prosta analiza linku pod kątem czarnych list (RBL)."""
        rbl_domains = ["bad-domain.com", "malware-site.org"]
        for domain in rbl_domains:
            if domain in link:
                logger.warning(f"Malicious link detected: {link}")
                return True
        return False

    def save_email(self, folder, mailfrom, rcpttos, data, analysis_results):
        """Zapisuje wiadomość do odpowiedniego folderu."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"{folder}/email_{timestamp}.txt"

        with open(file_name, "w", encoding="utf-8") as f:
            f.write(f"From: {mailfrom}\n")
            f.write(f"To: {', '.join(rcpttos)}\n")
            f.write(f"Analysis Results: {json.dumps(analysis_results)}\n")
            f.write("\n")
            f.write(data.decode("utf-8"))

        logger.info(f"Email saved to {file_name}")

    def update_report(self):
        """Aktualizuje raport JSON o statystykach."""
        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)

if __name__ == "__main__":
    # Uruchomienie serwera na localhost i porcie 1025
    server = EmailProxyServer(('127.0.0.1', 1025), None)
    logger.info("SMTP server running on 127.0.0.1:1025")
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        logger.info("SMTP server stopped.")
