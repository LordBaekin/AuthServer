# email_service.py - Email functions
import time  # email_service.py - Email functions
import re
import smtplib
import logging
import os
from email.message import EmailMessage
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import config

# Directory for user-customized templates
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

def load_templates():
    """
    Load all templates, falling back to the built-in EMAIL_TEMPLATES
    if no override file exists on disk.
    Returns a dict: template_name -> template_content
    """
    os.makedirs(TEMPLATE_DIR, exist_ok=True)
    result = {}
    for name, default in EMAIL_TEMPLATES.items():
        path = os.path.join(TEMPLATE_DIR, f"{name}.html")
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    result[name] = f.read()
            except Exception as e:
                logging.error(f"Failed to read template override {path}: {e}")
                result[name] = default
        else:
            result[name] = default
    return result

def save_template(name, content):
    """
    Save the given template content to disk so it persists
    across restarts. Overwrites or creates templates/<name>.html.
    """
    os.makedirs(TEMPLATE_DIR, exist_ok=True)
    path = os.path.join(TEMPLATE_DIR, f"{name}.html")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        logging.info(f"Template '{name}' saved to {path}")
        return True
    except Exception as e:
        logging.error(f"Failed to save template '{name}' to {path}: {e}")
        return False

# Built-in email templates
EMAIL_TEMPLATES = {
    'reset_password': '''
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }
        .container { padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .header { background-color: #4a6da7; color: white; padding: 10px; text-align: center; border-radius: 5px 5px 0 0; }
        .footer { font-size: 12px; color: #777; margin-top: 20px; text-align: center; }
        .button { display: inline-block; background-color: #4a6da7; color: white; padding: 10px 20px; 
                 text-decoration: none; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Reset Your Password</h2>
        </div>
        <p>Hello {{username}},</p>
        <p>We received a request to reset your Vespeyr account password.</p>
        <p>To reset your password, click the button below:</p>
        <p style="text-align: center;">
            <a href="{{reset_link}}" class="button">Reset Password</a>
        </p>
        <p>Or copy and paste this link into your browser:</p>
        <p>{{reset_link}}</p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
        <p>Best regards,<br>The Vespeyr Team</p>
        <div class="footer">
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
    ''',
    'password_changed': '''
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }
        .container { padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .header { background-color: #4a6da7; color: white; padding: 10px; text-align: center; border-radius: 5px 5px 0 0; }
        .footer { font-size: 12px; color: #777; margin-top: 20px; text-align: center; }
        .alert { color: #cc0000; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Password Changed</h2>
        </div>
        <p>Hello {{username}},</p>
        <p>Your Vespeyr account password was successfully changed on {{date}} from IP address {{ip_address}}.</p>
        <p>If you did not make this change, please <span class="alert">contact support immediately</span> as your account may have been compromised.</p>
        <p>Best regards,<br>The Vespeyr Team</p>
        <div class="footer">
            <p>This is an automated message, please do not reply to this email.</p>
            <p>For security purposes, please keep this email for your records.</p>
        </div>
    </div>
</body>
</html>
    ''',
    'welcome': '''
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }
        .container { padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .header { background-color: #4a6da7; color: white; padding: 10px; text-align: center; border-radius: 5px 5px 0 0; }
        .footer { font-size: 12px; color: #777; margin-top: 20px; text-align: center; }
        .button { display: inline-block; background-color: #4a6da7; color: white; padding: 10px 20px; 
                 text-decoration: none; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Welcome to Vespeyr!</h2>
        </div>
        <p>Hello {{username}},</p>
        <p>Thank you for creating your Vespeyr account. We're excited to have you onboard!</p>
        <p>Your account has been successfully created and is ready to use.</p>
        <p style="text-align: center;">
            <a href="{{login_link}}" class="button">Login to Your Account</a>
        </p>
        <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
        <p>Best regards,<br>The Vespeyr Team</p>
        <div class="footer">
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
    ''',
    'multi_reset_password': '''
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }
        .container { padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .header { background-color: #4a6da7; color: white; padding: 10px; text-align: center; border-radius: 5px 5px 0 0; }
        .footer { font-size: 12px; color: #777; margin-top: 20px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Password Reset Requested</h2>
        </div>
        <p>Hello,</p>
        <p>We received a password reset request for the following Vespeyr accounts registered under <b>{{email}}</b>:</p>
        {{accounts_html}}
        <p>Each link is valid for 1 hour.</p>
        <p>If you didn’t request this, you can safely ignore this email.</p>
        <p>— The Vespeyr Team</p>
        <div class="footer">
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
    '''
}


logger = logging.getLogger(__name__)

def send_email(to_email: str, subject: str, body: str, is_html: bool = False) -> bool:
    """
    Sends a raw email via SMTP with full debug logging.
    """
    host = config["SMTP_HOST"]
    port = config["SMTP_PORT"]
    user = config["SMTP_USER"]
    pwd  = config["SMTP_PASS"]

    logger.debug("SMTP: connecting to %s:%s", host, port)
    try:
        smtp = smtplib.SMTP(host, port, timeout=10)

        # Capture low-level protocol logs into our logger
        smtp.set_debuglevel(1)
        def _debug_printer(*args):
            line = " ".join(str(a) for a in args)
            logger.debug("SMTP-RAW: %s", line.strip())


        smtp._print_debug = _debug_printer

        logger.debug("SMTP: starting TLS")
        smtp.starttls()
        logger.debug("SMTP: logging in as %s", user)
        smtp.login(user, pwd)

        # Build the message
        msg = EmailMessage()
        msg["From"]    = config.get("SMTP_FROM_ADDRESS", user)
        msg["To"]      = to_email
        msg["Subject"] = subject
        if is_html:
            msg.add_header("Content-Type", "text/html")
        msg.set_content(body, subtype=("html" if is_html else "plain"))

        logger.debug("SMTP: sending message to %s", to_email)
        smtp.send_message(msg)
        smtp.quit()

        logger.info("SMTP: email successfully sent to %s", to_email)
        return True

    except Exception as e:
        # This will log the full stack trace
        logger.exception("SMTP: failed to send email to %s", to_email)
        return False

def send_template_email(to_email: str, template_name: str, subject: str, context: dict = None) -> bool:
    """
    Send an email using a template, allowing for on-disk overrides,
    with debug logging for every step.
    """
    logger.debug("send_template_email: start — template='%s', to='%s'", template_name, to_email)

    # 1) Load templates
    templates = load_templates()
    if template_name not in templates:
        logger.error("send_template_email: template '%s' not found", template_name)
        return False
    logger.debug("send_template_email: loaded template '%s'", template_name)

    # 2) Render body
    body = templates[template_name]
    context = context or {}
    for key, value in context.items():
        placeholder = f"{{{{{key}}}}}"
        body = body.replace(placeholder, str(value))
        logger.debug("send_template_email: replaced placeholder '%s' with '%s'", placeholder, value)
    logger.debug("send_template_email: final body length %d chars", len(body))

    # 3) Dispatch
    success = send_email(to_email, subject, body, is_html=True)
    logger.debug("send_template_email: send_email returned %s", success)
    return success
