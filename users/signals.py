from secrets import token_urlsafe as get_token_urlsafe

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import Permission

from users.models import Group, OneTimePassword, User
from users.actions import send_verification_email, send_notification_email


@receiver(post_save, sender=User)
def create_user(sender: type[User], instance: User, created: bool, **kwargs):
    """
    Handles user-related post-save actions:
    - On creation:
        * Generates and sends a one-time verification code via email.
        * Creates and assigns the 'Root' group to superusers.
    - On update:
        * Sends a notification email to the user.
    """
    if created:
        if not OneTimePassword.objects.filter(user=instance).exists():
            code = get_token_urlsafe(16)
            OneTimePassword.objects.create(user=instance, code=code)
            send_verification_email(instance, code)

        if instance.is_superuser:
            root_group, created_root = Group.objects.get_or_create(name='Root')
            if created_root:
                root_group.description = 'Superusers Group'
                all_permissions = Permission.objects.all()
                root_group.permissions.set(all_permissions)
                root_group.save()
            instance.groups.add(root_group)

    else:
        send_notification_email(instance)
    return
