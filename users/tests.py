from django.core.management import call_command
from django.test import TestCase

from io import StringIO
from unittest.mock import patch

from .models import User, Group, OneTimePassword


def create_user(username: str = None, email: str = None) -> User:
    data = {
        "email": email if email else "test@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "password": "password123",
    }
    if hasattr(User, "username"):
        data["username"] = username if username else "johnDoe"

    user = User.objects.create_user(**data)
    return user


class CommandsTests(TestCase):
    def setUp(self):
        # Create a test user
        self.user = create_user("existingUser", "existing@example.com")
        self.otp = OneTimePassword.objects.get(user=self.user)

    @patch("builtins.input")
    @patch("getpass.getpass")
    def test_create_user_command(self, mock_getpass, mock_input):
        username = "johnDoe" if hasattr(User, "username") else None

        # Simulate input responses
        mock_input.side_effect = [
            "test@example.com",  # email
            "John",           # first name
            "Doe",            # last name
        ]

        mock_input.side_effect.insert(0, username) if username else None

        # Simulate passwords
        mock_getpass.side_effect = ["password123",
                                    "password123"]

        # Run the create user command
        out = StringIO()
        call_command("createuser", stdout=out)

        # Check that the answer is correct
        self.assertIn(
            "created successfully", out.getvalue())

        # Verify that the user has been created in the database
        user = User.objects.get(email="test@example.com")
        self.assertEqual(user.first_name, "John")
        self.assertEqual(user.last_name, "Doe")
        self.assertEqual(user.is_staff, False)
        self.assertEqual(user.is_superuser, False)
        self.assertTrue(user.check_password("password123"))

    @patch("builtins.input")
    def test_create_user_existing_username(self, mock_input):
        username = "existingUser" if hasattr(User, "username") else None

        mock_input.side_effect = [
            "existing@example.com",
            "Alice",
            "Smith",
        ]

        mock_input.side_effect.insert(0, username) if username else None

        usersCount = User.objects.all().count()

        out = StringIO()
        call_command("createuser", stdout=out)
        self.assertIn(
            "already exists", out.getvalue())

        self.assertEqual(usersCount, User.objects.all().count())

    @patch("builtins.input")
    @patch("getpass.getpass")
    def test_create_staffuser_command(self, mock_getpass, mock_input):
        username = "johnDoe" if hasattr(User, "username") else None

        mock_input.side_effect = [
            "test@example.com",
            "John",
            "Doe",
        ]

        mock_input.side_effect.insert(0, username) if username else None

        mock_getpass.side_effect = ["password123",
                                    "password123"]

        out = StringIO()
        call_command("createstaffuser", stdout=out)

        self.assertIn(
            "created successfully", out.getvalue())

        user = User.objects.get(email="test@example.com")
        self.assertEqual(user.first_name, "John")
        self.assertEqual(user.last_name, "Doe")
        self.assertEqual(user.is_staff, True)
        self.assertEqual(user.is_superuser, False)
        self.assertTrue(user.check_password("password123"))

    @patch("builtins.input")
    def test_create_staffuser_existing_username(self, mock_input):
        username = "existingUser" if hasattr(User, "username") else None

        mock_input.side_effect = [
            "existing@example.com",
            "Alice",
            "Smith",
        ]

        mock_input.side_effect.insert(0, username) if username else None

        usersCount = User.objects.all().count()

        out = StringIO()
        call_command("createstaffuser", stdout=out)
        self.assertIn(
            "already exists", out.getvalue())

        self.assertEqual(usersCount, User.objects.all().count())

    @patch("builtins.input")
    def test_activate_user_with_valid_code(self, mock_input):
        mock_input.return_value = self.otp.code

        out = StringIO()
        call_command("activateuser", stdout=out)

        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)
        self.assertFalse(
            OneTimePassword.objects.filter(code=self.otp.code).exists()
        )
        self.assertIn("activated successfully", out.getvalue())

    @patch("builtins.input")
    def test_activate_user_with_invalid_code(self, mock_input):
        mock_input.return_value = "wrongcode"

        out = StringIO()
        call_command("activateuser", stdout=out)

        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)
        self.assertIn("does not exist", out.getvalue())


class UserModelTests(TestCase):
    def setUp(self):
        self.user = create_user()

    def test_full_name(self):
        self.assertEqual(self.user.full_name, "John Doe")

    def test_change_status(self):
        self.assertFalse(self.user.is_active)
        self.user.change_status(True)
        self.assertTrue(self.user.is_active)
        self.user.change_status(False)
        self.assertFalse(self.user.is_active)

    def test_change_password(self):
        self.user.set_password("newpassword123")
        self.user.save()
        self.assertTrue(self.user.check_password("newpassword123"))

    def test_delete_user(self):
        self.user.delete()
        self.assertFalse(User.objects.filter(
            email="test@example.com").exists())


class GroupModelTests(TestCase):
    def setUp(self):
        self.group: Group = Group()
        self.group = Group.objects.create(
            name="testgroup",
            description="Test Group Description"
        )

    def test_get_group(self):
        group = Group.objects.get(name="testgroup")
        self.assertEqual(group.description, "Test Group Description")

    def test_delete_group(self):
        self.group.delete()
        self.assertFalse(Group.objects.filter(
            name="testgroup").exists())


class OTPModelTest(TestCase):
    def setUp(self):
        self.user = create_user()

    def test_get_otp(self):
        otp = OneTimePassword.objects.get(user=self.user)
        self.assertIsInstance(otp.code, str)
        self.assertGreaterEqual(len(otp.code), 22)
        self.assertRegex(otp.code, r'^[A-Za-z0-9_-]+$')

    def test_delete_otp(self):
        otp = OneTimePassword.objects.get(user=self.user)
        otp.delete()
        self.assertFalse(OneTimePassword.objects.filter(
            user=self.user).exists())
