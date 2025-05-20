from django.core.management.base import BaseCommand

from djAuth.utils import getenv_or_error
from users.models import User, OneTimePassword


class Command(BaseCommand):
    help = "Initializes a default administrator user. Use only during first-time setup."

    def handle(self, *args, **options):
        if User.objects.filter(is_superuser=True).exists():
            self.stdout.write(self.style.ERROR(
                "A superuser already exists. Aborting."))
            return

        email = getenv_or_error("DEFAULT_ADMIN_EMAIL")
        password = getenv_or_error("DEFAULT_ADMIN_PASSWORD")

        user = User.objects.create_superuser(
            email=email,
            first_name="Admin",
            last_name="User",
            password=password,
        )

        user.change_status(True)
        OneTimePassword.objects.filter(user=user).delete()

        self.stdout.write(self.style.SUCCESS(
            f"Default admin user '{email}' created and activated successfully."))
