from rest_framework_simplejwt.views import TokenRefreshView
from django.urls import path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from .views import (
    RegisterView, LoginView, LogoutView, MeView,
    PasswordResetView, PasswordResetConfirmView,
    VendorRegistrationView, VendorListView, VendorDetailView,
    VendorApproveView, VendorRejectView, VendorSuspendView,
    VendorBanView, VendorDeleteView, VendorProductsView,
    ProductCreateView, ProductListView, ProductDetailView,
    ProductUpdateView, ProductDeleteView, VendorReviewsView,
    VendorReviewDeleteView, ProductReviewsView, ProductReviewDeleteView,
    CategoryListCreateView, CategoryDetailView, CategoryUpdateView, CategoryDeleteView,
    TagListCreateView, TagDetailView, TagUpdateView, TagDeleteView,
    CartView, CartAddItemView, CartUpdateItemView, CartRemoveItemView,
    WishlistView, WishlistAddItemView, WishlistRemoveItemView
)

urlpatterns = [
    # Swagger docs
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    path('schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),

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
    path('vendors/<int:vendor_id>/reviews/', VendorReviewsView.as_view(), name='vendor-reviews'),
    path('vendors/reviews/<int:pk>/delete/', VendorReviewDeleteView.as_view(), name='vendor-review-delete'),


    # Product management endpoints
    path('products/', ProductListView.as_view(), name='product-list'),
    path('products/create/', ProductCreateView.as_view(), name='product-create'),
    path('products/<int:product_id>/', ProductDetailView.as_view(), name='product-detail'),
    path('products/<int:product_id>/update/', ProductUpdateView.as_view(), name='product-update'),
    path('products/<int:product_id>/delete/', ProductDeleteView.as_view(), name='product-delete'),
    path('products/<int:product_id>/reviews/', ProductReviewsView.as_view(), name='product-reviews'),
    path('products/reviews/<int:pk>/delete/', ProductReviewDeleteView.as_view(), name='product-review-delete'),

    # Category endpoints
    path('categories/', CategoryListCreateView.as_view(), name='category-list-create'),
    path('categories/<int:pk>/', CategoryDetailView.as_view(), name='category-detail'),
    path('categories/<int:pk>/update/', CategoryUpdateView.as_view(), name='category-update'),
    path('categories/<int:pk>/delete/', CategoryDeleteView.as_view(), name='category-delete'),

    # Tag endpoints
    path('tags/', TagListCreateView.as_view(), name='tag-list-create'),
    path('tags/<int:pk>/', TagDetailView.as_view(), name='tag-detail'),
    path('tags/<int:pk>/update/', TagUpdateView.as_view(), name='tag-update'),
    path('tags/<int:pk>/delete/', TagDeleteView.as_view(), name='tag-delete'),

    # Cart & Wishlist endpoints
    path('cart/', CartView.as_view(), name='cart-detail'),
    path('cart/add/', CartAddItemView.as_view(), name='cart-add-item'),
    path('cart/update/<int:itemId>/', CartUpdateItemView.as_view(), name='cart-update-item'),
    path('cart/remove/<int:itemId>/', CartRemoveItemView.as_view(), name='cart-remove-item'),
    path('wishlist/', WishlistView.as_view(), name='wishlist-detail'),
    path('wishlist/<int:productId>/', WishlistAddItemView.as_view(), name='wishlist-add-item'),
    path('wishlist/remove/<int:productId>/', WishlistRemoveItemView.as_view(), name='wishlist-remove-item'),
]
