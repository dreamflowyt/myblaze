from flask import render_template, url_for
from flask_mail import Message
from app import app, mail
import logging
import os

logger = logging.getLogger(__name__)

def send_email(to, subject, template, **kwargs):
    """
    Helper function to send emails
    """
    try:
        # Using the EMAIL_USER from environment variables for both sender and username
        sender_email = os.environ.get('EMAIL_USER')
        if not sender_email:
            logger.error("EMAIL_USER environment variable is not set")
            return False
            
        msg = Message(subject, recipients=[to], sender=sender_email)
        msg.html = render_template(template, **kwargs)
        mail.send(msg)
        logger.info(f"Email sent to {to}: {subject}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to}: {str(e)}")
        return False

def send_verification_email(user):
    """
    Send email verification to a user
    """
    token = user.verification_token
    verify_url = url_for('verify_email', token=token, _external=True)
    success = send_email(
        to=user.email,
        subject='Verify Your Email - Blazer Chat',
        template='verification_email.html',
        user=user,
        verify_url=verify_url
    )
    
    if success:
        logger.info(f"Verification email sent to {user.email}")
    return success
