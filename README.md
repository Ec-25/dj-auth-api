# dj-auth


## **Description:**
This module is responsible for user authorization and authentication for server access.


## Table of Contents
- [Description](#description)
- [Required environment variables](#required-environment-variables)
    - [Optional variables](#optional-variables)
- [Main Classes and Methods](#main-classes-and-methods)
    - [Custom Management Commands](#custom-management-commands)
- [Endpoints](#endpoints)
- [Signals](#signals)
- [Run Server](#run-server)
- [Run Tests](#run-tests)


## Required environment variables
Before starting the application, make sure you have set the following variables in your environment or `.env` file:

```
SECRET_KEY="your-secret-key"  # Secret key for Django application
DEFAULT_ADMIN_EMAIL="email"  # Email for the default superuser
DEFAULT_ADMIN_PASSWORD="secret-password" # Password for the default superuser
EMAIL_HOST_USER="your-email"  # Email address for sending emails
EMAIL_HOST_PASSWORD="your-email-password"  # Email password
```

### Optional variables
These variables are optional and control the behavior of the application:

```
ALLOWED_HOSTS="host1,host2"    # Comma-separated list of allowed hosts
DEBUG="True"                   # Set to False in production environment for security
EMAIL_HOST="smtp.gmail.com"    # SMTP server for sending emails (default: smtp.gmail.com)
EMAIL_PORT="587"               # Port for SMTP (default: 587)
EMAIL_USE_TLS="True"           # Whether to use TLS for email (default: True)
```


## Main Classes and Methods
Explanation of the module's classes and functions:

### `UserManager`
#### `create_user(email, password, **extra_fields)`
#### `create_staffuser(email, password, **extra_fields)`
#### `create_superuser(email, password, **extra_fields)`
A custom manager to handle user creation and management.

### `User`
#### `__init__(email, username, first_name, last_name, password)`
Custom user model that uses email as a unique identifier, with fields for personal details and timestamps.

### `Group`
#### `__init__(name, description)`
Extends the default group model to include a description field.

### `OneTimePassword`
#### `__init__(user, code)`
Template for storing a one-time password (OTP) for a user.


## Custom Management Commands

This module also includes custom management commands for creating users interactively from the command line.

### `createuser` command
This command allows you to create a new regular user interactively. When running `python manage.py createuser`, the system will prompt you to input the user's details (username, email, first name, last name, and password) one by one, securely masking the password as you type it.

Example usage:
```
python manage.py createuser
```
It will prompt you for the following inputs:
- Username
- Email address
- First name
- Last name
- Password (masked input)

### `createstaffuser` command
Similar to `createuser`, this command will create a staff user interactively. The only difference is that the user will have staff permissions.

Example usage:
```
python manage.py createstaffuser
```
It will prompt you for the same details as `createuser`, but it will create a staff user.

### `createsuperuser` command
This is the default Django command for creating a superuser interactively, with admin permissions.

### `activateuser` command
Activates a user account associated with a valid one-time password (OTP) code.

### `initdefaultadmin` command
Creates a default superuser with credentials from environment variables (`DEFAULT_ADMIN_EMAIL`, `DEFAULT_ADMIN_PASSWORD`).  
Used in automated deployments. Only runs if no superuser exists.

⚠️ Make sure to change these credentials after setup in production.


## Endpoints
The following are the main endpoints for user-related actions:

### Users: `/auth/`
- `POST register/` - Register a new user in the system.
- `POST register/resend_email_verify/` - Resend the verification code to the user.
- `GET register/verify?code=` - Activate a registered user if the code is valid.
- `POST login/` - Log in with a user.
- `POST logout/` - Log out and invalidate the user token.
- `DELETE logout/` - Log out and invalidate all user tokens.
- `GET profile/view/` - Get user data.
- `GET profile/has_group/<str:group>/` - Check if a user has a group.
- `GET profile/has_permission/<str:permission>` - Check if a user has a permission.
- `PUT profile/update/` - Update user data.
- `DELETE profile/delete/` - Disable the system user.
- `POST password/request_change/` - Request a password change for a user using their email address.
- `GET password/verify/<str:uidb64>/<str:token>/` - Validate the data for changing your password.
- `PUT password/reset/` - Change the user's password.

### Administration: `/auth/admin/`
They require an authentication token and administrative permissions (`is_staff` or specific permissions).

- `users/` - CRUD of users
- `groups/` - CRUD of groups
- `permissions/` - CRUD of permissions


## Signals

### `handle_user_post_save`
Automatically triggered when a `User` instance is created or updated:
- When a user is created:
  - A one-time password (OTP) is generated and sent by email.
  - If the user is a superuser, they are assigned to the "Root" group with full permissions.

- When a user is updated:
  - A notification email is sent to inform about the update.


## Run Server
To start the server, run:

```bash
python manage.py runserver
```


## Run Tests
To run the unit tests:

```bash
python manage.py test
```
