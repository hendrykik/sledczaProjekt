class EmailHandler(AsyncMessage):
    def __init__(self):
        super().__init__()
        self.report = {
            "total_emails": 0,
            "spam_detected": 0,
            "dangerous_attachments": 0,
            "blacklisted_links": 0,
            "sandboxed_emails": 0,
        }

    async def handle_message(self, message):
        self.report["total_emails"] += 1
        email_subject = message.get("Subject", "(No Subject)")
        try:
            email_body = message.get_payload(decode=True).decode('utf-8', errors='replace')
        except AttributeError:
            email_body = "(No Body)"

        # Wykrywanie spamu
        if self._contains_spam(email_body):
            self.report["spam_detected"] += 1
            self._save_email(email_body, "spam", email_subject)
            return

        # Wykrywanie załączników z sygnaturami
        if self._scan_attachments_for_signatures(message):
            self.report["dangerous_attachments"] += 1
            self._save_email(email_body, "quarantine", email_subject)
            return

        # Wykrywanie czarnych list i złośliwych linków
        if self._has_blacklisted_or_malicious_links(email_body):
            self.report["blacklisted_links"] += 1
            self._save_email(email_body, "sandbox", email_subject)
            return

        # Analiza behawioralna
        if self._sandbox_behavioral_analysis(email_body):
            self.report["sandboxed_emails"] += 1
            self._save_email(email_body, "sandbox", email_subject)
            return

        # Bezpieczna wiadomość
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
                    if attachment_hash in KNOWN_BAD_HASHES:
                        logger.warning(f"Niebezpieczny załącznik wykryty: {part.get_filename()}")
                        return True
        return False

    def _has_blacklisted_or_malicious_links(self, body):
        urls = re.findall(r'http[s]?://\S+', body)
        for url in urls:
            domain = urlparse(url).netloc
            if domain in BLACKLISTED_DOMAINS or self._check_rbl(domain):
                logger.warning(f"Czarnolistny odnośnik wykryty: {domain}")
                return True
            if self._analyze_threat_intelligence(domain):
                logger.warning(f"Zagrożenie wykryte na podstawie Threat Intelligence: {domain}")
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
            logger.warning(f"Błąd podczas sprawdzania RBL dla {domain}: {e}")
        return False

    def _analyze_threat_intelligence(self, domain):
        try:
            # Rozszerz ten moduł według potrzeb
            return self._check_rbl(domain)
        except Exception as e:
            logger.warning(f"Analiza Threat Intelligence nie powiodła się dla {domain}: {e}")
            return False

    def _sandbox_behavioral_analysis(self, content):
        try:
            # Pseudokod dla analizy behawioralnej
            simulated_behavior = self._simulate_attachment_execution(content)
            if simulated_behavior in MALICIOUS_BEHAVIORS:
                logger.warning("Wykryto złośliwe zachowanie w załączniku.")
                return True
        except Exception as e:
            logger.warning(f"Analiza behawioralna nie powiodła się: {e}")
        return False

    def _simulate_attachment_execution(self, content):
        # Zintegrowane narzędzia sandboxingowe jak Cuckoo mogą być użyte tutaj
        return "safe"

    def _save_email(self, content, folder, subject):
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        safe_subject = re.sub(r'[^a-zA-Z0-9_-]', '_', subject)[:50]
        filepath = os.path.join(EMAIL_DIR, folder, f"{timestamp}_{safe_subject}.txt")

        os.makedirs(os.path.join(EMAIL_DIR, folder), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info(f"Wiadomość zapisana w {filepath}")

    def save_report(self):
        report_path = os.path.join(EMAIL_DIR, "report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(self.report, f, indent=4)

        logger.info(f"Raport zapisany w {report_path}")