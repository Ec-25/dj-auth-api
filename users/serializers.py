from django.contrib.auth import authenticate
from django.contrib.auth.models import Permission
from django.core.validators import validate_email

from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from users.actions import (send_verification_email, send_password_reset_email)
from users.models import Group, User, OneTimePassword
from users.utils import (
    get_tokens, get_user_id_by_uidb64, get_uidb64_by_user, make_token_for_password_reset,
    check_for_password_reset_user_token, delete_outstanding_token, delete_all_outstanding_tokens)


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile

    Fields:
    -------
    - instance: user

    Methods:
    --------
    - to_representation: returns user email and full name
    """

    def to_representation(self, instance):
        return {"email": instance.email, "full_name": instance.full_name}


class UserRegisterSerializer(serializers.Serializer):
    """
    Serializer for user registration

    Methods:
    --------
    - validate: validates user data
    - create: creates user

    Fields:
    -------
    Required:
    ---------
    - email: user email
    - first_name: user first name
    - last_name: user last name
    - password: user password
    - password2: user password confirmation

    Responses:
    ----------
    - Success: Returns the serialized User object upon creation.
    - Failure: Returns validation errors if required fields are missing or invalid.
    """

    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=100)
    last_name = serializers.CharField(max_length=100)
    password = serializers.CharField(
        max_length=100, min_length=8, write_only=True)
    password2 = serializers.CharField(
        max_length=100, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ["email", "first_name", "last_name", "password", "password2"]

    def validate(self, data):
        if User.objects.filter(email=data.get("email")).exists():
            raise serializers.ValidationError(
                {"invalid_email": "The email already exists"})

        password = data.get("password")
        password2 = data.pop("password2")

        if password != password2:
            raise serializers.ValidationError(
                {"passwords_do_not_match": "Passwords do not match"})

        if not any(char.isdigit() for char in password):
            raise serializers.ValidationError(
                {"password_no_number": "The password must contain at least one number"})

        if len(password) < 8:
            raise serializers.ValidationError(
                {"password_too_short": "The password must be at least 8 characters long."})

        return data

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class ResendVerifyEmailSerializer(serializers.Serializer):
    """
    Serializer for resending verification email

    Methods:
    --------
    - validate: validates user data

    Fields:
    -------
    Required:
    ---------
    - email: user email

    Responses:
    ----------
    - Success: Returns the serialized User object upon creation.
    - Failure: Returns validation errors if required fields are missing or invalid.
    """
    email = serializers.EmailField()
    user = None
    code = None

    def validate(self, data):
        email = data.get("email")

        if not email:
            raise serializers.ValidationError(
                {"message": "Email is required"})

        try:
            user = User.objects.get(email=email)

            if user.is_active:
                raise serializers.ValidationError(
                    {"message": "Email already verified"})

            code = OneTimePassword.objects.get(user=user)

            self.user = user
            self.code = code

        except User.DoesNotExist:
            raise serializers.ValidationError(
                {"message": "Email not found"})

        except OneTimePassword.DoesNotExist:
            raise serializers.ValidationError(
                {"message": "Verification code not found"})

        return data

    def resend_email(self):
        if self.user is None or self.code is None:
            raise serializers.ValidationError(
                {"message": "User or code not found"})

        send_verification_email(self.user, self.code.code)
        return


class VerifyEmailSerializer(serializers.Serializer):
    """
    Serializer for verifying user email

    Methods:
    --------
    - validate: validates user data

    Fields:
    -----
    Required:
    ---------
    - code: verification code

    Responses:
    ----------
    - Success: No return, but activates the user linked to the code.
    - Failure: Returns validation errors if required fields are missing or invalid.
    """

    code = serializers.CharField()

    def validate(self, data):
        code = data.get("code")

        if not code:
            raise serializers.ValidationError(
                {"message": "Code is required"})

        try:
            user_code_obj = OneTimePassword.objects.get(code=code)
            user = user_code_obj.user

            if user.is_active:
                raise serializers.ValidationError(
                    {"message": "Email already verified"})

            user.is_active = True
            user.save()
            user_code_obj.delete()

        except User.DoesNotExist:
            raise serializers.ValidationError(
                {"message": f"Invalid verification code - Error 1 - {code}"})

        except OneTimePassword.DoesNotExist:
            raise serializers.ValidationError(
                {"message": f"Invalid verification code - Error 2 - {code}"})

        return data


class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for user login

    Methods:
    --------
    - validate: validates user data

    Fields:
    -----
    Required:
    ---------
    - email: user email
    - password: user password

    Responses:
    ----------
    - Success: Returns serialized tokens to the user.
    - Failure: Returns validation errors if required fields are missing or invalid.
    """

    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(
        max_length=100, min_length=8, write_only=True)
    access_token = serializers.CharField(max_length=512, read_only=True)
    refresh_token = serializers.CharField(max_length=512, read_only=True)

    class Meta:
        model = User
        fields = ["email", "password", "access_token", "refresh_token"]

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        # Authenticate the user
        user = authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed({"message": "Invalid credentials"})
        if not user.is_active:
            raise AuthenticationFailed(
                {"message": "The account is not active"})

        return get_tokens(user)


class UserChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for changing user password. Send the email to reset the password

    Methods:
    --------
    - validate: validates user data

    Fields:
    -----
    Required:
    ---------
    - email: user email

    Responses:
    ----------
    - Success: No return, just send the email to reset the password.
    - Failure: Returns validation errors if required fields are missing or invalid.
    """

    email = serializers.EmailField()

    def validate(self, attrs):
        email = attrs.get("email")

        if not User.objects.filter(email=email).exists():
            raise AuthenticationFailed({"message": "Invalid credentials"})

        user = User.objects.get(email=email)

        codes = (get_uidb64_by_user(user),
                 make_token_for_password_reset(user))

        send_password_reset_email(user, codes)

        return super().validate(attrs)


class UserPasswordResetSerializer(serializers.Serializer):
    """
    Serializer for resetting user password

    Methods:
    --------
    - validate: validates user data
    - save: saves the new password

    Fields:
    -----
    Required:
    ---------
    - password: user password
    - password2: user password confirmation
    - uidb64: user id encoded in base64
    - token: user token

    Responses:
    ----------
    - Success: There is no return.
    - Failure: Returns validation errors if required fields are missing or invalid.
    """

    password = serializers.CharField(
        max_length=100, min_length=8, write_only=True)
    password2 = serializers.CharField(
        max_length=100, min_length=8, write_only=True)
    uidb64 = serializers.CharField(max_length=100, write_only=True)
    token = serializers.CharField(max_length=100, write_only=True)
    user_id = None
    new_password = None

    class Meta:
        fields = ["password", "password2", "uidb64", "token"]

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")

        if password != password2:
            raise serializers.ValidationError(
                "The passwords do not match, please enter again.")

        try:
            user = User.objects.get(
                id=get_user_id_by_uidb64(attrs.get("uidb64")))

            if not check_for_password_reset_user_token(user, attrs.get("token")):
                raise AuthenticationFailed("Invalid credentials")

            self.new_password = password
            self.user_id = user.id

            return True

        except User.DoesNotExist:
            raise AuthenticationFailed("Invalid credentials")

        except Exception as e:
            raise serializers.ValidationError(str(e))

    def save(self, **kwargs):
        if not (self.user_id and self.new_password):
            raise serializers.ValidationError("Invalid credentials")

        user = User.objects.get(id=self.user_id)

        user.set_password(self.new_password)
        user.save()

        delete_all_outstanding_tokens(self.user_id)
        return


class UserLogoutSerializer(serializers.Serializer):
    """
    Serializer for user logout

    Methods:
    --------
    - validate: validates user data
    - save: deletes the refresh token

    Fields:
    -----
    Required:
    ---------
    - refresh_token: user refresh token

    Responses:
    ----------
    - Success: There is no return.
    - Failure: Returns validation errors if required fields are missing or invalid.
    """

    refresh_token = serializers.CharField()

    def validate(self, attrs):
        self.refresh_token = attrs.get("refresh_token")
        return attrs

    def save(self, user_id, delete_all: bool = False, **kwargs):
        if delete_all:
            delete_all_outstanding_tokens(user_id)
            return
        delete_outstanding_token(user_id, self.refresh_token)
        return


class UserDeleteSerializer(serializers.Serializer):
    """
    Serializer for user delete

    Methods:
    --------
    - validate: validates user data
    - save: deletes the user

    Fields:
    -----
    Required:
    ---------
    - email: user email
    - password: user password

    Responses:
    ----------
    - Success: There is no return.
    - Failure: Returns validation errors if required fields are missing or invalid.
    """

    email = serializers.EmailField()
    password = serializers.CharField(
        max_length=100, min_length=8, write_only=True)

    class Meta:
        fields = ["email", "password"]

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")
        request = self.context.get("request")

        user = authenticate(request=request, email=email, password=password)

        if not user:
            raise AuthenticationFailed({"message": "Invalid credentials"})
        if not user.is_active:
            raise AuthenticationFailed(
                {"message": "The account is not active"})

        return data

    def save(self, user_id, **kwargs):
        user = User.objects.get(id=user_id)
        delete_all_outstanding_tokens(user_id)
        # delete the user completely
        # user.delete()

        # or disable the user
        user.is_active = False
        user.save(update_fields=['is_active'])

        return


class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for user update

    Methods:
    --------
    - validate: validates user data
    - update: updates the user
    - to_representation: returns user email and full name

    Fields:
    -----
    Optional:
    ---------
    - email: user email
    - first_name: user first name
    - last_name: user last name

    Responses:
    ----------
    - Success: Returns the serialized User object upon update.
    - Failure: Returns validation errors if required fields are missing or invalid.
    """

    email = serializers.EmailField(required=False)
    first_name = serializers.CharField(max_length=100, required=False)
    last_name = serializers.CharField(max_length=100, required=False)

    class Meta:
        model = User
        fields = ["email", "first_name", "last_name"]

    def validate(self, attrs, instance):
        new_email = attrs.get("email")

        if not new_email:
            first_name = attrs.get("first_name")
            last_name = attrs.get("last_name")

            if not first_name and not last_name:
                raise serializers.ValidationError(
                    "Please enter a field to edit: email, first_name, last_name.")

            if first_name and not (2 <= len(first_name) <= 100):
                raise serializers.ValidationError(
                    "The name must be between 2 and 255 characters.")

            if last_name and not (2 <= len(last_name) <= 100):
                raise serializers.ValidationError(
                    "The last name must be between 2 and 255 characters.")

            return super().validate(attrs)

        elif new_email == instance.email:
            return super().validate(attrs)

        elif User.objects.filter(email=new_email).exists():
            raise AuthenticationFailed(
                {"message": "The email address already exists, please enter another one."})

        try:
            validate_email(new_email)
        except Exception as error:
            raise serializers.ValidationError({"message": error})

        return super().validate(attrs)

    def update(self, instance, validated_data):
        instance.email = validated_data.get("email", instance.email)
        instance.first_name = validated_data.get(
            "first_name", instance.first_name)
        instance.last_name = validated_data.get(
            "last_name", instance.last_name)

        delete_all_outstanding_tokens(instance.id)
        instance.save()
        return instance

    def to_representation(self, instance):
        return {"email": instance.email, "full_name": instance.full_name}


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for user
    """
    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "password",
            "is_active",
            "is_staff",
            "is_superuser",
            "created_at",
            "updated_at",
            "last_login",
        ]
        read_only_fields = ["is_superuser",
                            "created_at", "updated_at", "last_login"]
        extra_kwargs = {
            "password": {"write_only": True},
        }

    def validate(self, attrs):
        password = attrs.get("password", None)
        if password and not (7 < len(password) < 256):
            raise serializers.ValidationError(
                "The password must be at least 8 characters.")
        return super().validate(attrs)

    def create(self, validated_data):
        password = validated_data.pop("password")
        is_staff = validated_data.pop("is_staff", False)
        if is_staff:
            user = User.objects.create_staffuser(
                password=password, **validated_data)
        else:
            user = User.objects.create_user(
                password=password, **validated_data)
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class GroupSerializer(serializers.ModelSerializer):
    """
    Serializer for group
    """
    permissions = serializers.PrimaryKeyRelatedField(
        queryset=Permission.objects.all(),
        many=True
    )

    class Meta:
        model = Group
        fields = ["id", "name", "description", "permissions"]


class PermissionSerializer(serializers.ModelSerializer):
    """
    Serializer for permission
    """
    class Meta:
        model = Permission
        fields = "__all__"
