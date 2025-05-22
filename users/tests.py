from django.core.management import call_command
from django.contrib.auth.models import Permission
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import OutstandingToken

from io import StringIO
from unittest.mock import patch

from users.models import User, Group, OneTimePassword
from users.utils import get_tokens, get_uidb64_by_user, make_token_for_password_reset


def get_response_data(response):
    return {"message": response.json().get("message"), "data": response.json().get("data")}


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


class UserApiTestCase(APITestCase):
    def setUp(self):
        self.base_url = "/api/auth/"

        self.user_password = "UserTest0"
        self.user = User.objects.create_user(
            email="testuser@user.net", password=self.user_password, first_name="Tester", last_name="User", is_active=True)

        self.tokens = get_tokens(self.user)

        return super().setUp()

    def test_user_register_view(self):
        url = f"{self.base_url}register/"

        data = {
            "email": "tester01@tester.net",
            "first_name": "Test",
            "last_name": "Ter",
            "password": "tester00",
            "password2": "tester00",
        }

        # Register
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(User.objects.count(), 2)
        user = User.objects.get(email="tester01@tester.net")
        self.assertEqual(user.first_name, "Test")
        self.assertEqual(user.last_name, "Ter")
        self.assertEqual(get_response_data(
            response).get("message"), "Registration successful")
        self.assertEqual(user.is_active, False)

        # Register Verify
        code = OneTimePassword.objects.get(user=user).code
        response = self.client.get(f"{url}verify?code={code}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(get_response_data(response).get(
            "message"), "Email Verification Successful")
        user = User.objects.get(email="tester01@tester.net")
        self.assertEqual(user.is_active, True)

    def test_user_register_view_fail(self):
        url = f"{self.base_url}register/"

        data = {
            "email": "XXXXXXXXXXXXXXXXXXX",
            "first_name": "Test",
            "last_name": "Ter",
            "password": "tester00",
            "password2": "tester00",
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 400)

        data = {
            "email": "tester01@tester.net",
            "first_name": "Test",
            "last_name": "Ter",
            "password": "XXXXXXXX",
            "password2": "tester00",
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 400)

        response = self.client.post(url, {})
        self.assertEqual(response.status_code, 400)

    def test_user_resend_email_verify_view(self):
        user = User.objects.create(
            email="test1@test.net", first_name="Test", last_name="Ter", password="tester011")

        url = f"{self.base_url}register/resend_email_verify/"
        data = {"email": "test1@test.net"}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(get_response_data(response).get(
            "message"), "Verification email sent successfully")

    def test_user_resend_email_verify_view_fail(self):
        url = f"{self.base_url}register/resend_email_verify/"
        data = {"email": "test@test.net"}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 400)

    def test_user_login_view(self):
        url = f"{self.base_url}login/"

        data = {"email": self.user.email, "password": self.user_password}

        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 200)

    def test_user_login_view_fail(self):
        url = f"{self.base_url}login/"

        data = {"email": "XXXXXXXXXXXXX", "password": "XXXXXXXX"}

        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 400)

        data = {"email": "XXXXXXXXXXXXXXXXXXX", "password": "XXXXXXXX"}

        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 400)

        response = self.client.post(url, {})
        self.assertEqual(response.status_code, 400)

    def test_user_logout_view(self):
        url = f"{self.base_url}logout/"
        url_login = f"{self.base_url}login/"

        data = {"email": self.user.email, "password": self.user_password}
        rp = self.client.post(url_login, data)
        rp = self.client.post(url_login, data)
        rp = self.client.post(url_login, data)
        self.assertEqual(rp.status_code, 200)

        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer " + rp.data["access_token"])
        response = self.client.delete(
            url, {"refresh_token": rp.data["refresh_token"]})
        self.assertEqual(response.status_code, 204)

        user_id = User.objects.get(email=self.user.email).id
        outstanding_tokens_count = OutstandingToken.objects.filter(
            user_id=user_id
        ).count()
        self.assertEqual(outstanding_tokens_count, 0)

    def test_user_logout_view_fail(self):
        url = f"{self.base_url}logout/"
        response = self.client.delete(url, {})
        self.assertEqual(response.status_code, 401)

        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer " + self.tokens["access_token"])
        response = self.client.delete(url, {})
        self.assertEqual(response.status_code, 400)

    def test_user_profile_view(self):
        url = f"{self.base_url}profile/view/"
        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer " + self.tokens["access_token"])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["email"], self.user.email)
        self.assertEqual(response.data["full_name"], self.user.full_name)

    def test_user_profile_view_fail(self):
        url = f"{self.base_url}profile/view/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 401)

    def test_user_profile_update_view(self):
        url = f"{self.base_url}profile/update/"
        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer " + self.tokens["access_token"])
        data = {"first_name": "StMod"}
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.get(id=1).first_name, "StMod")

    def test_user_profile_update_view_fail(self):
        url = f"{self.base_url}profile/update/"
        data = {"full_name": "StMod, Ter"}
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, 401)

        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer " + self.tokens["access_token"])
        response = self.client.put(url, {"email": "emailFake"})
        self.assertEqual(response.status_code, 400)

    def test_user_delete_view(self):
        url = f"{self.base_url}profile/delete/"
        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer " + self.tokens["access_token"])
        response = self.client.delete(
            url, {"email": self.user.email, "password": self.user_password})
        self.assertEqual(response.status_code, 204)
        self.assertEqual(User.objects.count(), 1)

    def test_user_delete_view_fail(self):
        url = f"{self.base_url}profile/delete/"
        response = self.client.delete(url, {})
        self.assertEqual(response.status_code, 401)

        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer " + self.tokens["access_token"])
        response = self.client.delete(url, {})
        self.assertEqual(response.status_code, 400)

    def test_user_has_group_view(self):
        url = f"{self.base_url}profile/has_group/"
        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer " + self.tokens["access_token"])
        response = self.client.get(url + "Super Users Group/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["has_group"], False)

        group = Group.objects.create(name="New Group")

        User.objects.get(id=1).groups.add(group)
        response = self.client.get(url + f"{group.name}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["has_group"], True)

    def test_user_has_permission_view(self):
        url = f"{self.base_url}profile/has_permission/"
        permission = Permission.objects.get(id=1)
        perm_name = "admin.add_logentry"

        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer " + self.tokens["access_token"])
        response = self.client.get(url + perm_name)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["has_permission"], False)

        User.objects.get(id=1).user_permissions.add(permission)

        response = self.client.get(url + perm_name)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["has_permission"], True)

    def test_request_change_valid_email(self):
        url = reverse("user-password-request-change")
        response = self.client.post(url, {"email": self.user.email})
        self.assertEqual(response.status_code, 200)
        self.assertIn("We've sent you a link to reset your password",
                      get_response_data(response).get("message"))

    def test_request_change_invalid_email(self):
        url = reverse("user-password-request-change")
        response = self.client.post(url, {"email": "nonexistent@example.com"})
        self.assertEqual(response.status_code, 401)
        self.assertIn("Error", get_response_data(response).get("message"))

    def test_user_password_verify_valid_token(self):
        # Generate valid token
        valid_token = make_token_for_password_reset(self.user)
        uidb64 = get_uidb64_by_user(self.user)
        url = reverse("user-password-reset", args=[uidb64, valid_token])

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(get_response_data(
            response).get("message"), "Valid codes")

    def test_user_password_verify_invalid_token(self):
        uidb64 = get_uidb64_by_user(self.user)
        url = reverse("user-password-reset", args=[uidb64, "invalid-token"])

        response = self.client.get(url)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(get_response_data(response).get("message"),
                         "Invalid or expired codes")

    def test_user_password_verify_invalid_uidb64(self):
        fakeUser = User(id=99999)
        uidb64 = get_uidb64_by_user(fakeUser)
        valid_token = make_token_for_password_reset(self.user)
        url = reverse("user-password-reset", args=[uidb64, valid_token])

        response = self.client.get(url)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(get_response_data(response).get("message"),
                         "Invalid or expired codes")

    def test_reset_password_success(self):
        token = make_token_for_password_reset(self.user)
        uidb64 = get_uidb64_by_user(self.user)
        url = reverse('user-password-reset')

        data = {
            'password': 'newpassword123',
            'password2': 'newpassword123',
            'uidb64': uidb64,
            'token': token,
        }

        response = self.client.put(url, data, format='json')

        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()  # Refreshes user data from the database
        self.assertTrue(self.user.check_password('newpassword123'))

    def test_reset_password_invalid_token(self):
        token = "invalid-token"
        uidb64 = get_uidb64_by_user(self.user)
        url = reverse('user-password-reset')

        data = {
            'password': 'newpassword123',
            'password2': 'newpassword123',
            'uidb64': uidb64,
            'token': token,
        }

        response = self.client.put(url, data, format='json')

        self.assertEqual(response.status_code, 400)

    def test_reset_password_non_matching_passwords(self):
        token = make_token_for_password_reset(self.user)
        uidb64 = get_uidb64_by_user(self.user)
        url = reverse('user-password-reset')

        data = {
            'password': 'newpassword123',
            'password2': '123newpassword',
            'uidb64': uidb64,
            'token': token,
        }

        response = self.client.put(url, data, format='json')

        self.assertEqual(response.status_code, 400)


class UserModelViewSetTest(APITestCase):
    def setUp(self):
        self.user_password = "UserTest0"
        self.user = User(email="test@example.com", password=self.user_password, first_name="Tester",
                         last_name="User", is_active=True, is_superuser=True, is_staff=True)
        self.user.save()
        self.tokens = get_tokens(self.user)
        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer " + self.tokens["access_token"])

    def test_list_users(self):
        url = reverse("admin-users-list")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["email"], "test@example.com")

    def test_retrieve_user(self):
        url = reverse("admin-users-detail", args=[self.user.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], "test@example.com")

    def test_create_user(self):
        url = reverse("admin-users-list")
        data = {
            "email": "user@new.net",
            "first_name": "User",
            "last_name": "New",
            "password": "userPassword",
            "is_staff": True
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["is_staff"], True)
        self.assertEqual(response.data["is_active"], False)

    def test_update_user(self):
        url = reverse("admin-users-detail", args=[self.user.id])
        data = {"email": "updated@example.com"}
        response = self.client.patch(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], "updated@example.com")

    def test_delete_user(self):
        url = reverse("admin-users-detail", args=[self.user.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_unauthorized(self):
        url = reverse("admin-users-list")
        self.client.logout()
        data = {"email": "newuser@example.com", "password": "newpassword"}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class GroupModelViewSetTest(APITestCase):
    def setUp(self):
        self.user_password = "UserTest0"
        self.user = User(email="test@example.com", password=self.user_password, first_name="Tester",
                         last_name="User", is_active=True, is_superuser=True, is_staff=True)
        self.user.save()
        self.tokens = get_tokens(self.user)
        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer " + self.tokens["access_token"])

    def test_create_group(self):
        url = reverse("admin-groups-list")
        data = {
            "name": "NewGroup",
            "description": "new group",
            "permissions": [1, 2, 3, 4]
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_list_group(self):
        url = reverse("admin-groups-list")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_retrieve_group(self):
        url = reverse("admin-groups-detail", args=[1])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_update_group(self):
        url = reverse("admin-groups-detail", args=[1])
        data = {
            "name": "NewGroupMOD",
            "description": "new group"
        }
        response = self.client.patch(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_delete_group(self):
        url = reverse("admin-groups-detail", args=[1])
        response = self.client.delete(url)
        self.assertEqual(response.status_code,
                         status.HTTP_405_METHOD_NOT_ALLOWED)


class PermissionModelViewSetTest(APITestCase):
    def setUp(self):
        self.user_password = "UserTest0"
        self.user = User(email="test@example.com", password=self.user_password, first_name="Tester",
                         last_name="User", is_active=True, is_superuser=True, is_staff=True)
        self.user.save()
        self.tokens = get_tokens(self.user)
        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer " + self.tokens["access_token"])

    def test_list_permissions(self):
        url = reverse("admin-permissions-list")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_retrieve_permission(self):
        url = reverse("admin-permissions-detail", args=[1])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_list_logout(self):
        url = reverse("admin-permissions-list")
        self.client.logout()
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
