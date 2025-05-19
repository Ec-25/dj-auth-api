from django.contrib.auth.models import BaseUserManager


class UserManager(BaseUserManager):
    """
    Custom manager for handling user creation and management.
    """

    def create_user(self, email, password=None, **extra_fields):
        """
        Creates and saves a standard user with the given email and password.
        """
        if not email:
            raise ValueError("Email is required")

        user = self.model(email=self.normalize_email(email), **extra_fields)

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_staffuser(self, email, password=None, **extra_fields):
        """
        Creates and saves a staff user with is_staff=True and is_superuser=False.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", False)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("The superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not False:
            raise ValueError("The superuser must have is_superuser=False.")

        return self.create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Creates and saves a superuser with is_staff=True and is_superuser=True.
        Generates an OTP token for two-factor authentication.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("The superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("The superuser must have is_superuser=True.")

        user = self.create_user(email, password, **extra_fields)

        return user
