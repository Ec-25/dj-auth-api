from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.models import Permission

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.viewsets import ReadOnlyModelViewSet
from rest_framework.response import Response

from users.viewsets import ModelViewSet
from users.permissions import HasModelPermission, IsAdmin, IsAuthenticatedAndTokenValid, IsStaffOrAdmin
from users.models import User, Group
from users.serializers import (
    GroupSerializer,
    PermissionSerializer,
    UserRegisterSerializer,
    ResendVerifyEmailSerializer,
    VerifyEmailSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    UserChangePasswordSerializer,
    UserPasswordResetSerializer,
    UserLogoutSerializer,
    UserDeleteSerializer,
    UserUpdateSerializer,
    UserSerializer
)


class UserRegisterView(APIView):
    """
    This class is only used to register a user (not staff, not superuser)

    Methods:
    --------
    - post(request): Register a user in the database

    Body:
    -----
    Required:
    ---------
    - email: str
    - first_name: str
    - last_name: str
    - password: str
    - password2: str

    Responses:
    ----------
    - 201: User registered successfully
    - 400: Bad request
    """

    serializer_class = UserRegisterSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "Registration successful"}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResendVerifyEmail(APIView):
    """
    This class is only used to resend a user's email verification

    Methods:
    --------
    - post(request): Resend a user's email verification

    Body:
    -----
    Required:
    ---------
    - email: str

    Responses:
    ----------
    - 200: Email sent successfully
    - 400: Bad request
    """

    serializer_class = ResendVerifyEmailSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.resend_email()
            return Response({"message": "Verification email sent successfully"}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmail(APIView):
    """
    This class is only used to verify a user's email

    Methods:
    --------
    - get(request): Verify a user's email

    Headers:
    --------
    - code: str
        - The verification code sent to the user's email

    Responses:
    ----------
    - 200: Email verified successfully
    - 400: Bad request or invalid verification code
    """

    serializer_class = VerifyEmailSerializer

    def get(self, request):
        serializer = self.serializer_class(
            data={"code": request.GET.get("code")})
        if serializer.is_valid(raise_exception=True):
            return Response({"message": "Email Verification Successful"}, status=status.HTTP_200_OK)
        else:

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    """
    This class is only used to login a user

    Methods:
    --------
    - post(request): Login a user

    Body:
    -----
    Required:
    ---------
    - email: str
    - password: str

    Responses:
    ----------
    - 200: User logged in successfully
    - 400: Bad request or invalid credentials
    """

    serializer_class = UserLoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    """
    This class is only used to get a user's profile

    Methods:
    --------
    - get(request): Get a user's profile

    Headers:
    --------
    - Authorization: Bearer <access_token>

    Responses:
    ----------
    - 200: User profile
    - 400: Bad request
    """

    permission_classes = [IsAuthenticatedAndTokenValid]
    serializer_class = UserProfileSerializer

    def get(self, request):
        serializer = self.serializer_class(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class HasGroup(APIView):
    """
    This class is only used to check if a user has a group

    Methods:
    --------
    - get(request): Check if a user has a group

    Headers:
    --------
    - Authorization: Bearer <access_token>

    Responses:
    ----------
    - 200: User has group
    - 400: Bad request
    """

    permission_classes = [IsAuthenticatedAndTokenValid]

    def get(self, request, group):
        user = request.user

        has_group = user.groups.filter(name=group).exists()
        return Response({"has_group": has_group}, status=status.HTTP_200_OK)


class HasPermission(APIView):
    """
    This class is only used to check if a user has a permission

    Methods:
    --------
    - get(request): Check if a user has a permission

    Headers:
    --------
    - Authorization: Bearer <access_token>

    Responses:
    ----------
    - 200: User has permission
    - 400: Bad request
    """

    permission_classes = [IsAuthenticatedAndTokenValid]

    def get(self, request, permission):
        user = request.user

        has_perm = user.has_perm(permission)
        return Response({"has_permission": has_perm}, status=status.HTTP_200_OK)


class UserChangePasswordView(APIView):
    """
    This class is only used to change a user's password

    Methods:
    --------
    - post(request): Change a user's password

    Body:
    -----
    Required:
    ---------
    - email: str

    Responses:
    ----------
    - 200: Email sent to reset password
    - 400: Bad request
    """

    serializer_class = UserChangePasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid(raise_exception=True):
            return Response(
                {"message": "We've sent you a link to reset your password"},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserPasswordVerifyResetView(APIView):
    """
    This class is only used to verify a user's password reset

    Methods:
    --------
    - get(request): Verify a user's password reset

    Headers:
    --------
    - uidb64: str
    - token: str

    Responses:
    ----------
    - 200: User password reset verified
    - 401: Unauthorized
    """

    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response(
                    data={"message": "Invalid or expired codes"}, status=status.HTTP_401_UNAUTHORIZED
                )

            return Response(data={"message": "Valid codes"}, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError:
            return Response(
                data={"message": "Invalid or expired codes"}, status=status.HTTP_401_UNAUTHORIZED
            )

        except User.DoesNotExist:
            return Response(
                data={"message": "Invalid or expired codes"}, status=status.HTTP_401_UNAUTHORIZED
            )


class UserPasswordResetView(APIView):
    """
    This class is only used to reset a user's password

    Methods:
    --------
    - put(request): Reset a user's password

    Body:
    -----
    Required:
    ---------
    - password: str
    - password2: str
    - uidb64: str
    - token: str

    Responses:
    ----------
    - 200: Password reset successfully
    - 400: Bad request
    """

    serializer_class = UserPasswordResetSerializer

    def put(self, request):
        serializer = self.serializer_class(data=request.data)
        # raise_exception=True : (returns error response from the serializer itself)
        # raise_exception=False : (returns error response described in else)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "Password reset successfully"}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)


class UserLogoutView(APIView):
    """
    This class is only used to logout a user

    Methods:
    --------
    - post(request): Logout a user
    - delete(request): Logout a user from all devices

    Headers:
    --------
    - Authorization: Bearer <access_token>

    Body:
    -----
    Required:
    ---------
    - refresh_token: str

    Responses:
    ----------
    - 204: User logged out successfully
    - 400: Bad request
    """

    permission_classes = [IsAuthenticatedAndTokenValid]
    serializer_class = UserLogoutSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save(user_id=request.user.id, delete_all=False)
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save(user_id=request.user.id, delete_all=True)
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserDeleteView(APIView):
    """
    This class is only used to delete a user

    Methods:
    --------
    - delete(request): Delete a user

    Headers:
    --------
    - Authorization: Bearer <access_token>

    Body:
    -----
    Required:
    ---------
    - email: str
    - password: str

    Responses:
    ----------
    - 204: User deleted successfully
    - 400: Bad request
    """

    permission_classes = [IsAuthenticatedAndTokenValid]
    serializer_class = UserDeleteSerializer

    def delete(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save(user_id=request.user.id)
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserUpdateView(APIView):
    """
    This class is only used to update a user's profile

    Methods:
    --------
    - put(request): Update a user's profile

    Headers:
    --------
    - Authorization: Bearer <access_token>

    Body:
    -----
    Required:
    ---------
    - email: str
    - first_name: str
    - last_name: str

    Responses:
    ----------
    - 204: User updated successfully
    - 400: Bad request
    """

    permission_classes = [IsAuthenticatedAndTokenValid]
    serializer_class = UserUpdateSerializer

    def put(self, request):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request}
            )
            serializer.validate(
                request.data, User.objects.get(id=request.user.id))
            serializer.update(User.objects.get(
                id=request.user.id), request.data)
            return Response({"message": "User data modified successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(e.__dict__, status=status.HTTP_400_BAD_REQUEST)


class UserModelViewSet(ModelViewSet):
    """
    This class is used to manage users, only for Administrators and Staff
    """
    model = User
    queryset = User.objects.all()
    serializer_class = UserSerializer
    action_permissions = {
        "create": [IsStaffOrAdmin],
        "list": [IsStaffOrAdmin],
        "retrieve": [IsStaffOrAdmin],
        "update": [IsStaffOrAdmin],
        "partial_update": [IsStaffOrAdmin],
        "destroy": [IsStaffOrAdmin],
    }


class GroupModelViewSet(ModelViewSet):
    """
    This class is used to manage groups, only for Administrators and Staff
    """
    model = Group
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    action_permissions = {
        "create": [IsStaffOrAdmin],
        "list": [IsStaffOrAdmin],
        "retrieve": [IsStaffOrAdmin],
        "update": [IsStaffOrAdmin],
        "partial_update": [IsStaffOrAdmin],
        "destroy": [IsAdmin],
    }

    def destroy(self, request, *args, **kwargs):
        self.method_not_allowed("DELETE")


class PermissionModelViewSet(ReadOnlyModelViewSet):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticatedAndTokenValid,
                          HasModelPermission, IsStaffOrAdmin]
