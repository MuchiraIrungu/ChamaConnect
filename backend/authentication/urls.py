from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

app_name = "authentication"

urlpatterns = [
    path("register/",views.RegisterView.as_view(),name="register"),
    path("login/",views.LoginView.as_view(),name="login"),
    path("logout/",views.LogoutView.as_view(),name="logout"),
    path("token/refresh/",TokenRefreshView.as_view(),name="token_refresh"),
    path("profile/",views.ProfileView.as_view(),name="profile"),
    path("password/change/", views.ChangePasswordView.as_view(), name="password_change"),
    path("password/reset/", views.ResetPasswordView.as_view(),  name="password_reset"),
    path("otp/request/", views.RequestOTPView.as_view(), name="otp_request"),
    path("otp/verify/", views.VerifyOTPView.as_view(),name="otp_verify"),
    path("delete/request/", views.RequestAccountDeletionView.as_view(), name="delete_request"),
    path("delete/confirm/", views.ConfirmAccountDeletionView.as_view(), name="delete_confirm"),
]