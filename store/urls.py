from rest_framework_simplejwt.views import TokenRefreshView
from django.urls import path
from .views import (
    RegisterView, LoginView, LogoutView, MeView,
    PasswordResetView, PasswordResetConfirmView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='auth-register'),
    path('login/', LoginView.as_view(), name='auth-login'),
    path('logout/', LogoutView.as_view(), name='auth-logout'),
    path('me/', MeView.as_view(), name='auth-me'),
    path('refresh-token/', TokenRefreshView.as_view(), name='token-refresh'),
    path('password-reset/', PasswordResetView.as_view(), name='password-reset'),
    path('password-reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
]
