from getpass import getpass
from django.core.management.base import BaseCommand
from users.models import OneTimePassword


class Command(BaseCommand):
    help = "Activate a user with a code"

    def handle(self, *args, **options):
        code = input("Enter OTP Code: ").strip()

        try:
            otp = OneTimePassword.objects.get(code=code)

        except OneTimePassword.DoesNotExist:
            self.stdout.write(self.style.ERROR(
                f"Code '{code}' does not exist"))
            return

        user = otp.user
        user.is_active = True
        user.save()
        otp.delete()

        self.stdout.write(self.style.SUCCESS(
            f"User {user.email} activated successfully"))
