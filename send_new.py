import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os

#Zmienne globalne do testów
FILE_NAME = "pierdoly/OnlineFix64.dll"


# Konfiguracja email
SMTP_SERVER = '127.0.0.1'
SMTP_PORT = 1025
SENDER_EMAIL = "test@example.com"
RECIPIENT_EMAIL = "recipient@example.com"

def sendSimpleEmail():
    """Wysyła prosty e-mail z treścią tekstową."""
    subject = "Test prosty email"
    body = "To jest najprostszy email z tekstem"

    message = MIMEMultipart()
    message['From'] = SENDER_EMAIL
    message['To'] = RECIPIENT_EMAIL
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    sendEmail(message)

def sendEmailWithAttachment():
    """Wysyła e-mail z plikiem z repozytorium."""
    subject = f"Test Email with {FILE_NAME}"
    body = f"This email contains the file {FILE_NAME} for testing."

    message = MIMEMultipart()
    message['From'] = SENDER_EMAIL
    message['To'] = RECIPIENT_EMAIL
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    file_path = os.path.join(os.getcwd(), FILE_NAME)
    if not os.path.exists(file_path):
        print(f"Plik '{FILE_NAME}' nie został znaleziony w katalogu '{os.getcwd()}'.")
        return

    with open(file_path, "rb") as attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())
    encoders.encode_base64(part)
    part.add_header(
        "Content-Disposition",
        f"attachment; filename={os.path.basename(file_path)}",
    )
    message.attach(part)

    sendEmail(message)

def sendHttpEmailWithLink():
    """Wysyła e-mail z linkiem HTTP w treści."""
    subject = "Test Email with HTTP Link"
    body = "This is a test email. Check out this link: https://freegogpcgames.com/"

    message = MIMEMultipart()
    message['From'] = SENDER_EMAIL
    message['To'] = RECIPIENT_EMAIL
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    sendEmail(message)


def sendEmail(message):
    """Wysyła wiadomość e-mail za pomocą skonfigurowanego serwera SMTP."""
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.send_message(message)
            print(f"Email '{message['Subject']}' sent successfully!")
    except Exception as e:
        print(f"Failed to send email '{message['Subject']}': {e}")

if __name__ == "__main__":
    #sendSimpleEmail()
    sendHttpEmailWithLink()
    #sendEmailWithAttachment()
    #send_email_with_links()
    #send_spam_email()