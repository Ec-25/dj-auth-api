from pathlib import Path
import json

from django.core.mail import EmailMessage


def get_json_data(dir_json_file: Path) -> dict:
    """Load data from a JSON file"""
    try:
        with open(dir_json_file, "r") as json_file:
            data = json.load(json_file)

    except FileNotFoundError:
        data = {"error": "File not found"}

    except json.JSONDecodeError:
        data = {"error": "Invalid JSON"}

    return data


def send_email(subject: str, message: str, to_email: str):
    """Send an email with the given subject, message, and recipient."""
    email = EmailMessage(subject, message, to=[to_email])
    email.send(fail_silently=True)
    return
