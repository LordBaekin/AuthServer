import time# email_service.py - Email functions
import re
import smtplib
import logging
from email.message import EmailMessage
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import config

# Email templates
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
    '''
}

def send_email(to_email, subject, body, is_html=False):
    """Send an email with support for HTML content"""
    try:
        # Use either MIMEText or EmailMessage based on needs
        if is_html:
            msg = MIMEMultipart('alternative')
            msg['From'] = config["SMTP_USER"]
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Attach both plain text and HTML versions
            text_part = MIMEText(re.sub('<[^<]+?>', '', body), 'plain')
            html_part = MIMEText(body, 'html')
            
            msg.attach(text_part)
            msg.attach(html_part)
        else:
            msg = EmailMessage()
            msg['From'] = config["SMTP_USER"]
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.set_content(body)
        
        with smtplib.SMTP(config["SMTP_HOST"], config["SMTP_PORT"]) as smtp:
            smtp.starttls()
            smtp.login(config["SMTP_USER"], config["SMTP_PASS"])
            smtp.send_message(msg)
        
        logging.info(f"Email sent to {to_email}: {subject}")
        return True
    except Exception as e:
        logging.error(f"Failed to send email: {str(e)}")
        return False

def send_template_email(to_email, template_name, subject, context=None):
    """Send an email using a template"""
    if template_name not in EMAIL_TEMPLATES:
        logging.error(f"Email template '{template_name}' not found")
        return False
        
    template = EMAIL_TEMPLATES[template_name]
    context = context or {}
    
    # Replace template variables
    body = template
    for key, value in context.items():
        placeholder = '{{' + key + '}}'
        body = body.replace(placeholder, str(value))
    
    return send_email(to_email, subject, body, is_html=True)
