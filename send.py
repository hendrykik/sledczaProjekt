import smtplib

# Ustawienia serwera SMTP
SMTP_SERVER = "127.0.0.1"
SMTP_PORT = 1025

# Treść wiadomości
message = """\
From: sender@example.com
To: receiver@example.com
Subject: Test Email

This is a test email sent from Python.
"""

# Wysyłanie wiadomości
with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
    server.sendmail("sender@example.com", "receiver@example.com", message)
    print("Email sent successfully!")
