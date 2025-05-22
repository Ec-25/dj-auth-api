from rest_framework import status
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet as BaseModelViewSet
from rest_framework.exceptions import *

from users.permissions import HasModelPermission, IsAuthenticatedAndTokenValid


class ModelViewSet(BaseModelViewSet):
    action_permissions = {
        "create": [],
        "list": [],
        "retrieve": [],
        "update": [],
        "partial_update": [],
        "destroy": [],
    }
    disable_instead_of_delete = True

    def get_permissions(self):
        """Adjust permissions based on the action; if not met, return HTTP_403_FORBIDDEN"""
        permission_classes = [
            IsAuthenticatedAndTokenValid,
            HasModelPermission,
            *self.action_permissions.get(self.action, []),
        ]
        return [permission() for permission in permission_classes]

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return response

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return response

    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        return response

    def destroy(self, request, *args, **kwargs):
        """Disables a model instance if `disable_instead_of_delete` is set to True"""
        if self.disable_instead_of_delete:
            instance = self.get_object()

            # Check if the model supports `change_status`
            if not callable(getattr(instance, 'change_status', None)):
                return Response(
                    {"detail": f"Model {type(instance).__name__} does not support disabling instances."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Disables the instance
            instance.change_status(False)
            return Response({"message": "Resource successfully disabled."}, status=status.HTTP_204_NO_CONTENT)

        response = super().destroy(request, *args, **kwargs)
        return response

    def method_not_allowed(self, method_name):
        """
        Helper to throw a 405 error
        """
        raise MethodNotAllowed(method_name)

    def model_not_found(self, msg=""):
        """
        Helper to throw a 404 error
        """
        raise NotFound({"detail": msg})
