# dj-auth

## **Description:**
This module is responsible for user authorization and authentication for server access.

## Table of Contents
- [Description](#description)
- [Required environment variables](#required-environment-variables)
    - [Optional variables](#optional-variables)

## Required environment variables
Before starting the application, make sure you have set the following variables in your environment or `.env` file:

```
SECRET_KEY="your-secret-key"  # Secret key for Django application
```

### Optional variables
These variables are optional and control the behavior of the application:

```
ALLOWED_HOSTS="host1,host2"    # Comma-separated list of allowed hosts
DEBUG="True"                   # Set to False in production environment for security
```
