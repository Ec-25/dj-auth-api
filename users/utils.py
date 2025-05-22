from pathlib import Path
import json

from django.core.mail import EmailMessage
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import smart_bytes, force_str

from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, OutstandingToken, TokenError


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


def get_tokens(self):
    """Returns a dict of access and refresh tokens"""
    refresh = RefreshToken.for_user(self)
    return {
        "refresh_token": str(refresh),
        "access_token": str(refresh.access_token),
    }


def get_user_id_by_uidb64(uidb64):
    """
    Get the user id from the uidb64 string.
    uidb64 is the base64 encoded user id.
    Returns the user id as an integer.
    """
    return force_str(urlsafe_base64_decode(uidb64))


def get_uidb64_by_user(user):
    """Get the uidb64 string from the user object"""
    return urlsafe_base64_encode(smart_bytes(user.id))


def make_token_for_password_reset(user):
    """Make a token for password reset"""
    return PasswordResetTokenGenerator().make_token(user)


def check_for_password_reset_user_token(user, token):
    """Check if the user and token are valid for password reset"""
    return PasswordResetTokenGenerator().check_token(user, token)


def delete_outstanding_token(user_id, refresh_token):
    """Delete one outstanding tokens for a given user"""
    try:
        token = OutstandingToken.objects.get(
            user_id=user_id, token=refresh_token)
        token.delete()
        return

    except OutstandingToken.DoesNotExist:
        raise AuthenticationFailed("Invalid refresh token!")

    except TokenError:
        raise AuthenticationFailed("Invalid refresh token!")


def delete_all_outstanding_tokens(user_id):
    """Deletes all outstanding tokens for a given user"""
    tokens = OutstandingToken.objects.filter(user_id=user_id)
    for token in tokens:
        token.delete()
    return
