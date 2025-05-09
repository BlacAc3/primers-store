from rest_framework_simplejwt.views import TokenRefreshView
from django.urls import path
from .views import (
    RegisterView, LoginView, LogoutView, MeView,
    PasswordResetView, PasswordResetConfirmView,
    VendorRegistrationView, VendorListView, VendorDetailView,
    VendorApproveView, VendorRejectView, VendorSuspendView,
    VendorBanView, VendorDeleteView, VendorProductsView,
    ProductCreateView, ProductListView, ProductDetailView,
    ProductUpdateView, ProductDeleteView
)

urlpatterns = [
    # Authentication endpoints
    path('register/', RegisterView.as_view(), name='auth-register'),
    path('login/', LoginView.as_view(), name='auth-login'),
    path('logout/', LogoutView.as_view(), name='auth-logout'),
    path('me/', MeView.as_view(), name='auth-me'),
    path('refresh-token/', TokenRefreshView.as_view(), name='token-refresh'),
    path('password-reset/', PasswordResetView.as_view(), name='password-reset'),
    path('password-reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),


    # Vendor management endpoints
    path('vendors/register/', VendorRegistrationView.as_view(), name='vendor-register'),
    path('vendors/', VendorListView.as_view(), name='vendor-list'),
    path('vendors/<int:vendor_id>/', VendorDetailView.as_view(), name='vendor-detail'),
    path('vendors/<int:vendor_id>/approve/', VendorApproveView.as_view(), name='vendor-approve'),
    path('vendors/<int:vendor_id>/reject/', VendorRejectView.as_view(), name='vendor-reject'),
    path('vendors/<int:vendor_id>/suspend/', VendorSuspendView.as_view(), name='vendor-suspend'),
    path('vendors/<int:vendor_id>/ban/', VendorBanView.as_view(), name='vendor-ban'),
    path('vendors/<int:vendor_id>/delete/', VendorDeleteView.as_view(), name='vendor-delete'),
    path('vendors/<int:vendor_id>/products/', VendorProductsView.as_view(), name='vendor-products'),


    # Product management endpoints
    path('products/', ProductListView.as_view(), name='product-list'),
    path('products/create/', ProductCreateView.as_view(), name='product-create'),
    path('products/<int:product_id>/', ProductDetailView.as_view(), name='product-detail'),
    path('products/<int:product_id>/update/', ProductUpdateView.as_view(), name='product-update'),
    path('products/<int:product_id>/delete/', ProductDeleteView.as_view(), name='product-delete'),
]
