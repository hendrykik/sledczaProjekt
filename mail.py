import smtpd
import asyncore
import logging

# Konfiguracja loggera
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EmailProxyServer(smtpd.SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        logger.info(f'Received email from: {mailfrom}')
        logger.info(f'To: {rcpttos}')
        logger.info(f'Data:\n{data.decode("utf-8")}')
        EmailProxyServer.inspect_email(mailfrom, rcpttos, data)

    @staticmethod
    def inspect_email(mailfrom, rcpttos, data):
        # Możesz dodać tutaj dowolne przetwarzanie wiadomości.
        logger.info("Inspecting email...")
        logger.info(f"Mail from: {mailfrom}")
        logger.info(f"Recipients: {rcpttos}")
        logger.info(f"Content:\n{data.decode('utf-8')}")

if __name__ == "__main__":
    # Uruchomienie serwera na localhost i porcie 1025
    server = EmailProxyServer(('127.0.0.1', 1025), None)
    logger.info("SMTP server running on 127.0.0.1:1025")
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        logger.info("SMTP server stopped.")
