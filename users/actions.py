from django.conf import settings

from users.models import User
from users.utils import get_json_data, send_email


def send_verification_email(user: User, code: str):
    """Send a verification email to the user."""
    # Load message from a JSON file
    json_data = get_json_data(
        settings.USERS_JSON_PATHS.get("verification_email"))

    # Send the email with the data
    send_email(
        subject=json_data["subject"],
        message=json_data["message"].format(
            name=user.full_name, code=code
        ),
        to_email=user.email,
    )
    return


def send_notification_email(user: User):
    """Send a update notification email to the user."""
    # Load message from a JSON file
    json_data = get_json_data(
        settings.USERS_JSON_PATHS.get("notification_email"))

    # Send the email with the data
    send_email(
        subject=json_data["subject"],
        message=json_data["message"].format(
            name=user.full_name),
        to_email=user.email,
    )
    return


def send_password_reset_email(user: User, codes: tuple[str]):
    """Send a password reset email to the user."""
    # Load message from a JSON file
    json_data = get_json_data(
        settings.USERS_JSON_PATHS.get("reset_password_email"))

    # Send the email with the data
    send_email(
        subject=json_data["subject"],
        message=json_data["message"].format(
            name=user.full_name, code0=codes[0], code1=codes[1]
        ),
        to_email=user.email,
    )
    return
