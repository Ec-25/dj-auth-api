#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Check for any Django issues
python manage.py check

# Collect static files
python manage.py collectstatic --no-input

# Apply database migrations
python manage.py migrate

# Create a default admin user (only if one doesn't exist)
python manage.py initdefaultadmin
