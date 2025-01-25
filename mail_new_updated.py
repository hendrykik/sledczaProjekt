import hashlib
from aiosmtpd.controller import Controller
import logging
import os
from aiosmtpd.handlers import AsyncMessage
from datetime import datetime
import re
import json
import logging
import pandas as pd
import apis

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("EmailHandler")

EMAIL_DIR = "emails"
REPORT_FILE = os.path.join(EMAIL_DIR, "report.json")
SPAM_KEYWORDS_FILE = 'spam_words.csv'
DANGEROUS_EXTENSIONS = [".exe", ".bat", ".js"]
DANGEROUS_URLS_FILE = "dangerous_urls.json"
RBL_SERVERS = ["zen.spamhaus.org", "b.barracudacentral.org"]
os.makedirs(os.path.join(EMAIL_DIR, "inbox"), exist_ok=True)
os.makedirs(os.path.join(EMAIL_DIR, "spam"), exist_ok=True)
os.makedirs(os.path.join(EMAIL_DIR, "quarantine"), exist_ok=True)
os.makedirs(os.path.join(EMAIL_DIR, "sandbox"), exist_ok=True)

def loadDangerousUrls():
    if os.path.exists(DANGEROUS_URLS_FILE):
        with open(DANGEROUS_URLS_FILE, "r", encoding="utf-8") as f:
            try:
                data = f.read().strip()
                if not data:
                    return set()
                return set(json.loads(data))
            except json.JSONDecodeError:
                print("Błąd dekodowania JSON w pliku.")
                return set()
    return set()

def loadSpamKeywords(spamKeywordsFile):
    df = pd.read_csv(spamKeywordsFile)

    print(df.columns)
    return df['Spam_words'].tolist()


DANGEROUS_URLS = loadDangerousUrls()
SPAM_KEYWORDS = loadSpamKeywords(SPAM_KEYWORDS_FILE)

class EmailHandler(AsyncMessage):
    def __init__(self):
        super().__init__()
        self.report = self.loadReport()

    async def handle_message(self, message):
        self.report["total_emails"] += 1
        email_subject = message.get("Subject", "(No Subject)")
        email_body = self.extractEmailBody(message)
        attachments = self.extractAttachmentsInfo(message)
        if attachments:
            logger.info(f"Załączniki znalezione w e-mailu: {attachments}")

        logger.info(f"Email body being checked for spam...")
        if self.containsSpam(email_body):
            self.report["spam_detected"] += 1
            self.saveEmail(email_body, "spam", email_subject, attachments)
            self.saveReport()
            return

        logger.info("Checking for dangerous attachments...")
        if self.hasDangerousAttachments(message) | self.scanAttachmentsForSignatures(message):
            self.report["dangerous_attachments"] += 1
            self.saveEmail(email_body, "quarantine", email_subject, attachments)
            self.saveReport()
            return
        
        logger.info("Checking for blacklisted or malicious links...")
        if self.hasBlacklistedOrMaliciousLinks(email_body):
            self.report["blacklisted_links"] += 1
            self.report["sandboxed_emails"] += 1
            self.saveEmail(email_body, "sandbox", email_subject, attachments)
            self.saveReport()
            return

        self.saveEmail(email_body, "inbox", email_subject, attachments)
        self.saveReport()

    def containsSpam(self, body):
        for keyword in SPAM_KEYWORDS:
            if keyword in body.lower():
                logger.info(f"Spam keyword detected: '{keyword}' in email body.")
                return True
        logger.info("No spam keywords detected in email body.")
        return False
    
    def scanAttachmentsForSignatures(self, message):
        if not message.is_multipart():
            return False

        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                content = part.get_payload(decode=True)
                if content:
                    attachment_hash = hashlib.sha256(content).hexdigest()
                    print("Attachment hash: ", attachment_hash)
                    hash_data = apis.checkHashWithCircl(attachment_hash)
                    print("Hash data: ", hash_data)
                    if hash_data:
                        logger.warning(f"Niebezpieczny załącznik wykryty: {part.get_filename()} - {hash_data}")
                        return True
        return False

    def hasDangerousAttachments(self, message):
        """Sprawdza, czy wiadomość zawiera niebezpieczne załączniki korzystając z Hybrid Analysis API."""
        if not message.is_multipart():
            return False

        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                content = part.get_payload(decode=True)
                if content:
                    maliciousCount, totalReports, tScore, susCount = apis.fileCheck(content, filename)
                    if tScore > 20:
                        logger.warning(f"Niebezpieczny załącznik wykryty przez Hybrid Analysis: {filename}")
                        logger.warning(f"Threat Score: {tScore}")
                        logger.warning(f"{maliciousCount}/{totalReports} raportów oznaczonych jako *malicious*.")
                        logger.warning(f"{susCount}/{totalReports} raportów oznaczonych jako *suspicious*.")
                        return True
                    else:
                        logger.warning(f"Załącznik {filename} bezpieczny")
        return False

    def hasBlacklistedOrMaliciousLinks(self, body):
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
        print("URLs found in email: ", urls)
        maliciousUrlCounter = 0
        for url in urls:
            logger.info(f"Checking URL: {url}")
            if url in DANGEROUS_URLS:
                logger.warning(f"URL {url} already marked as dangerous in local list.")
                maliciousUrlCounter += 1
                continue
            else:
                maliciousCount, totalReports, tScore, susCount = apis.urlCheck(url)
            if tScore > 20:
                logger.warning(f"Niebezpieczny link wykryty przez Hybrid Analysis: {url}")
                logger.warning(f"Threat Score: {tScore}")
                logger.warning(f"{maliciousCount}/{totalReports} raportów oznaczonych jako *malicious*.")
                logger.warning(f"{susCount}/{totalReports} raportów oznaczonych jako *suspicious*.")
                DANGEROUS_URLS.add(url)
                self.saveDangerousUrls()
                maliciousUrlCounter += 1
            else:
                logger.warning(f"link {url} jest bezpieczny")
        
        if maliciousUrlCounter > 0:
            logger.warning(f"Znaleziono {maliciousUrlCounter} niebezpiecznych linków w e-mailu.")
            return True
        return False

    def extractEmailBody(self, message):
        """Wyodrębnia treść e-maila, obsługując zarówno tekst, jak i HTML."""
        if message.is_multipart():
            for part in message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Szukamy części tekstowej
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    return part.get_payload(decode=True).decode('utf-8', errors='replace')
                
                # Jeśli chcesz używać treści HTML zamiast tekstowej, możesz dodać warunek dla text/html
                elif content_type == "text/html" and "attachment" not in content_disposition:
                    return part.get_payload(decode=True).decode('utf-8', errors='replace')
        else:
            return message.get_payload(decode=True).decode('utf-8', errors='replace')

        return "(No Body)"
    
    def extractAttachmentsInfo(self, message):
        """Sprawdza załączniki w wiadomości i zwraca listę nazw plików."""
        attachments = []
        if message.is_multipart():
            for part in message.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                if "attachment" in content_disposition:
                    filename = part.get_filename() or "(Unnamed Attachment)"
                    attachments.append(filename)
        return attachments

    def saveEmail(self, content, folder, subject, attachments):
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        safe_subject = re.sub(r'[^a-zA-Z0-9_-]', '_', subject)[:50]
        filename = f"{timestamp}_{safe_subject}.txt"
        filepath = os.path.join(EMAIL_DIR, folder, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"Subject: {subject}\n")
            f.write(f"Attachments: {', '.join(attachments) if attachments else 'None'}\n")
            f.write("\n")
            f.write(content)

        logger.info(f"Email saved to {filepath}")

    def loadReport(self):
        """Wczytuje raport z pliku, jeśli istnieje."""
        if os.path.exists(REPORT_FILE):
            try:
                with open(REPORT_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Nie udało się wczytać raportu: {e}")
        return {
            "total_emails": 0,
            "spam_detected": 0,
            "dangerous_attachments": 0,
            "blacklisted_links": 0,
            "sandboxed_emails": 0
        }
    
    def saveReport(self):
        """Zapisuje raport do pliku."""
        try:
            with open(REPORT_FILE, "w", encoding="utf-8") as f:
                json.dump(self.report, f, indent=4)
            logger.info(f"Raport zapisany do {REPORT_FILE}")
        except IOError as e:
            logger.error(f"Nie udało się zapisać raportu: {e}")

    def saveDangerousUrls(self):
        """Zapisuje listę niebezpiecznych URL-i do pliku."""
        with open(DANGEROUS_URLS_FILE, "w", encoding="utf-8") as f:
            json.dump(list(DANGEROUS_URLS), f, indent=4)

        
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
        handler.saveReport()
