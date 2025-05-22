from rest_framework.permissions import BasePermission
from rest_framework_simplejwt.tokens import (
    RefreshToken,
    AccessToken,
    OutstandingToken,
    TokenError,
)

from datetime import datetime, timezone


class IsAuthenticatedAndTokenValid(BasePermission):
    """
    Allows access only to authenticated users.
    """

    def has_permission(self, request, view):
        if not bool(request.user and request.user.is_authenticated):
            # User is not authenticated, token cannot be verified.
            return False

        # Get the Authorization header token
        authorization_header = request.headers.get("Authorization")
        if not authorization_header or not authorization_header.startswith("Bearer "):
            return False  # Authorization header is invalid

        try:
            bearer_token = authorization_header.split(" ")[1]
            access_token = AccessToken(bearer_token)

            iat = datetime.fromtimestamp(
                access_token.get("iat"), tz=timezone.utc)
            exp = datetime.fromtimestamp(
                access_token.get("exp"), tz=timezone.utc)

            outstanding_tokens = OutstandingToken.objects.get_queryset().filter(
                user_id=access_token.get("user_id")
            )
            outstanding_token = None

            for token in outstanding_tokens:
                if (
                    token.expires_at.strftime("%Y-%m-%d %H:%M:%S")
                    == exp.strftime("%Y-%m-%d %H:%M:%S")
                ) and (
                    token.created_at.strftime("%Y-%m-%d %H:%M:%S")
                    == iat.strftime("%Y-%m-%d %H:%M:%S")
                ):
                    # Check if the token is valid and has not expired.
                    if token.expires_at <= datetime.now(tz=timezone.utc):
                        return False

                    outstanding_token = token
                    break  # Valid token found.

            if not outstanding_token:
                return False  # The token does not exist or has expired.

            refresh_token = RefreshToken(outstanding_token.token)
            refresh_token.check_blacklist()

            return True  # The token is valid and the user is authenticated.

        except TokenError:
            return False  # The token is invalid

        except Exception as e:
            return False


class IsAdmin(BasePermission):
    """
    Allows access only to admin users.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_superuser)


class IsStaffOrAdmin(BasePermission):
    """
    Allows access only to admin users.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_staff or request.user.is_superuser)


class IsStaff(BasePermission):
    """
    Allows access only to staff users.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_staff)


class HasModelPermission(BasePermission):
    """
    Permission that checks whether the user has individual or group permissions to perform the action on a specific model.
    """

    def has_permission(self, request, view):
        # Determine the action
        action = view.action
        model_name = view.queryset.model._meta.model_name
        app_label = view.queryset.model._meta.app_label

        # Mapping DRF actions to Django permissions
        action_to_permission = {
            "list": f"view_{model_name}",
            "retrieve": f"view_{model_name}",
            "create": f"add_{model_name}",
            "update": f"change_{model_name}",
            "partial_update": f"change_{model_name}",
            "destroy": f"delete_{model_name}",
        }

        # Obtain the corresponding permit
        required_permission = action_to_permission.get(action)

        if not required_permission:
            # If the action is not in the mapping, deny the permission by default
            return False

        # Check if the user has the permission
        return request.user.has_perm(f"{app_label}.{required_permission}")
