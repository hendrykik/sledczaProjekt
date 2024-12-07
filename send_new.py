import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Email configuration
SMTP_SERVER = '127.0.0.1'
SMTP_PORT = 1025

# Email content
sender_email = "test@example.com"
recipient_email = "recipient@example.com"
subject = "Test Email"
body = "This is a test email sent to verify the SMTP server."

# Create the email message
message = MIMEMultipart()
message['From'] = sender_email
message['To'] = recipient_email
message['Subject'] = subject

# Attach the plain text body
message.attach(MIMEText(body, 'plain'))

try:
    # Connect to the SMTP server
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        # Send the email
        server.send_message(message)
        print("Email sent successfully!")
except Exception as e:
    print(f"Failed to send email: {e}")