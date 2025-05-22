from django.urls import include, path
from rest_framework.routers import DefaultRouter

from users.views import (
    GroupModelViewSet,
    PermissionModelViewSet,
    UserRegisterView,
    ResendVerifyEmail,
    VerifyEmail,
    UserLoginView,
    UserLogoutView,
    UserProfileView,
    HasGroup,
    HasPermission,
    UserUpdateView,
    UserDeleteView,
    UserChangePasswordView,
    UserPasswordVerifyResetView,
    UserPasswordResetView,
    UserModelViewSet
)

router = DefaultRouter()
router.register(r"admin/users", UserModelViewSet, basename="admin-users")
router.register(r"admin/groups", GroupModelViewSet, basename="admin-groups")
router.register(r"admin/permissions", PermissionModelViewSet, basename="admin-permissions")

urlpatterns = [
    path("", include(router.urls)),
    path("register/", UserRegisterView.as_view(), name="register"),
    path("register/resend_email_verify/", ResendVerifyEmail.as_view(), name="resend-verify-email"),
    path("register/verify", VerifyEmail.as_view(), name="verify-email"),
    path("login/", UserLoginView.as_view(), name="login"),
    path("logout/", UserLogoutView.as_view(), name="logout"),
    path("profile/view/", UserProfileView.as_view(), name="profile-view"),
    path("profile/has_group/<str:group>/", HasGroup.as_view(), name="profile-has-group"),
    path("profile/has_permission/<str:permission>", HasPermission.as_view(), name="profile-has-permission"),
    path("profile/update/", UserUpdateView.as_view(), name="profile-edit"),
    path("profile/delete/", UserDeleteView.as_view(), name="profile-delete"),
    path("password/request_change/", UserChangePasswordView.as_view(), name="user-password-request-change"),
    path("password/verify/<str:uidb64>/<str:token>/", UserPasswordVerifyResetView.as_view(), name="user-password-reset"),
    path("password/reset/", UserPasswordResetView.as_view(), name="user-password-reset"),
]
