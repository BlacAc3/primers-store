from decimal import Decimal
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from django.db.models import Q

from rest_framework import generics, status, filters, permissions,serializers
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenRefreshView
# from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes

from .serializers import (
    ProductCreateSerializer, ProductListSerializer, ProductUpdateSerializer, RegisterSerializer, LoginSerializer, LogoutSerializer,
    UserSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer,
    VendorRegistrationSerializer, VendorSerializer,
    VendorApproveSerializer, VendorRejectSerializer, VendorSuspendSerializer, VendorBanSerializer, VendorReviewSerializer,
    ProductCreateSerializer, ProductListSerializer, ProductDetailSerializer,ProductUpdateSerializer, ProductReviewSerializer,
    CategorySerializer, TagSerializer,
    CartSerializer, CartItemSerializer, AddCartItemSerializer,UpdateCartItemSerializer,
    WishlistSerializer, WishlistItemSerializer,
    OrderSerializer, CartOrderSerializer, OrderStatusUpdateSerializer,
)

from .models import Vendor, Product, Category, Tag, VendorReview, ProductReview, Cart, CartItem, Wishlist, WishlistItem,Order

from .permissions import IsAdmin, IsVendorOrAdmin, IsVendor, IsCustomer, AllowAny, IsAuthenticated, IsVendorOwnerOrAdmin, IsOwnerOfOrder

User = get_user_model()

def send_reset_email(user, request):
    uid = urlsafe_base64_encode(str(user.pk).encode()).encode()
    token = PasswordResetTokenGenerator().make_token(user)
    reset_link = f"{request.scheme}://{request.get_host()}/password-reset/confirm/?uid={uid}&token={token}"
    send_mail(
        'Password Reset',
        f'Use this link to reset your password: {reset_link}',
        'no-reply@primersstore.com',
        [user.email]
    )

@extend_schema(
    description="Register a new user",
    request=RegisterSerializer,
    responses={
        201: RegisterSerializer,
        400: {
            "type": "object",
            "properties": {
                "error": {
                    "type": "string",
                    "description": "Error message if registration fails"
                }
            }
        },
    }
)
class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            email = serializer.validated_data.get('email')
            username = serializer.validated_data.get('username')

            # Check for existing user with same email or username
            if User.objects.filter(email=email).exists():
                return Response(
                    {"error": "A user with this email already exists."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if User.objects.filter(username=username).exists():
                return Response(
                    {"error": "A user with this username already exists."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # If no duplicates, proceed with registration
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

@extend_schema(
    description="Login and obtain JWT token",
    request=LoginSerializer,
    responses={
        200: {
            "type": "object",
            "properties": {
                'refresh': {"type": "string", "description": "Refresh token"},
                'access': {"type": "string", "description": "Access token"},
                'user': {"type": "object", "description": "User details"}
            },
            "description": "Successfully logged in"
        },
        400: {
            "type": "object",
            "properties": {
                "error": {"type": "string", "description": "Error message"}
            },
            "description": "Bad request - invalid credentials"
        }
    }
)
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)

@extend_schema(
    description="Logout and invalidate JWT token",
    request=LogoutSerializer,
    responses={
        204: {
            "description": "No content - logout successful"
        },
        400: {
            "type": "object",
            "properties": {
                "error": {"type": "string", "description": "Error message"}
            },
            "description": "Bad request - invalid token"
        }
    }
)
class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

@extend_schema(
    description="Get current user details",
    responses={
        200: UserSerializer,
        401: {
            "type": "object",
            "properties": {
                "detail": {"type": "string", "description": "Error message"}
            },
            "description": "Unauthorized - not authenticated"
        }
    }
)
class MeView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_object(self):
        return self.request.user

@extend_schema(
    description="Refresh JWT token",
    request=None,  # No explicit request body, refresh token is passed in headers.
    parameters=[
        OpenApiParameter(name='refresh', type=OpenApiTypes.STR, location=OpenApiParameter.HEADER, required=True, description="Refresh token")
    ],
    responses={
        200: {
            "type": "object",
            "properties": {
                'access': {"type": "string", "description": "New access token"},
            },
            "description": "Successfully refreshed token"
        },
        401: {
            "type": "object",
            "properties": {
                "detail": {"type": "string", "description": "Error message"}
            },
            "description": "Unauthorized - invalid refresh token"
        }
    }
)
class RefreshTokenView(TokenRefreshView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

@extend_schema(
    description="Request password reset email",
    request=PasswordResetSerializer,
    responses={
        200: {
            "type": "object",
            "properties": {'detail': {"type": "string", "description": "Success message"}},
            "description": "Success: If email exists, reset link sent."
        },
        400: {
            "type": "object",
            "properties": {
                "email": {"type": "array", "items": {"type": "string"}, "description": "List of email errors"}
            },
            "description": "Bad request - invalid email format"
        }
    }
)
class PasswordResetView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.filter(email=serializer.validated_data['email']).first()
        if user:
            send_reset_email(user, request)
        return Response({'detail': 'If email exists, reset link sent.'}, status=status.HTTP_200_OK)

@extend_schema(
    description="Confirm password reset with token",
    request=PasswordResetConfirmSerializer,
    responses={
        200: {
            "type": "object",
            "properties": {'detail': {"type": "string", "description": "Success message"}},
            "description": "Password has been reset."
        },
        400: {
            "type": "object",
            "properties": {'error': {"type": "string", "description": "Error message"}},
            "description": "Bad request - invalid token or UID"
        }
    }
)
class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        uid = force_str(urlsafe_base64_decode(serializer.validated_data['uid']))
        user = User.objects.get(pk=uid)
        token = serializer.validated_data['token']
        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        return Response({'detail': 'Password has been reset.'}, status=status.HTTP_200_OK)



# Vendor Views
# --------------------
@extend_schema(
    description="Submit vendor registration request",
    request=VendorRegistrationSerializer,
    responses={
        201: VendorSerializer,  # Changed to VendorSerializer to show the created vendor
        400: {
            "type": "object",
            "properties": {
                "error": {"type": "string", "description": "Error message"}
            },
            "description": "Bad request - invalid data"
        }
    }
)
class VendorRegistrationView(generics.CreateAPIView):
    serializer_class = VendorRegistrationSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == status.HTTP_201_CREATED:
            # Send notification to admin about new vendor registration
            # This could be implemented with signals or directly here
            vendor = Vendor.objects.get(id=response.data['id'])
            send_mail(
                'New Vendor Registration',
                f'A new vendor has registered: {vendor.business_name}',
                'no-reply@primersstore.com',
                ['admin@primersstore.com']  # Admin email
            )
        return response

@extend_schema(
    description="List all vendors (with status filter)",
    parameters=[
        OpenApiParameter(name='status', type=OpenApiTypes.STR, description="Filter by vendor status",
                         enum=[status[0] for status in Vendor.STATUS_CHOICES], location=OpenApiParameter.QUERY),
    ],
    responses={
        200: VendorSerializer(many=True),
        401: {
            "type": "object",
            "properties": {
                "detail": {"type": "string", "description": "Authentication required"}
            },
            "description": "Unauthorized"
        },
        403: {
            "type": "object",
            "properties": {
                "detail": {"type": "string", "description": "Permission denied"}
            },
            "description": "Forbidden - not an admin"
        }
    }
)
class VendorListView(generics.ListAPIView):
    serializer_class = VendorSerializer
    permission_classes = [IsAdmin]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['business_name', 'user__username', 'user__email']
    ordering_fields = ['created_at', 'business_name', 'status']

    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        queryset = Vendor.objects.all().select_related('user')
        status_param = self.request.query_params.get('status')
        if status_param:
            queryset = queryset.filter(status=status_param)
        return queryset

@extend_schema(
    description="Get vendor details",
    responses={
        200: VendorSerializer,
        401: {
            "type": "object",
            "properties": {
                "detail": {"type": "string", "description": "Authentication required"}
            },
            "description": "Unauthorized"
        },
        403: {
            "type": "object",
            "properties": {
                "detail": {"type": "string", "description": "Permission denied"}
            },
            "description": "Forbidden - not an admin"
        },
        404: {
            "type": "object",
            "properties": {
                "detail": {"type": "string", "description": "Vendor not found"}
            },
            "description": "Vendor not found"
        }
    }
)
class VendorDetailView(generics.RetrieveAPIView):
    serializer_class = VendorSerializer
    permission_classes = [IsAdmin]
    queryset = Vendor.objects.all().select_related('user')
    lookup_url_kwarg = 'vendor_id'

    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


@extend_schema(
    description="Approve vendor",
    request=None,
    responses={
        200: VendorSerializer,
        401: {
            "type": "object",
            "properties": {
                "detail": {"type": "string", "description": "Authentication required"}
            },
            "description": "Unauthorized"
        },
        403: {
            "type": "object",
            "properties": {
                "detail": {"type": "string", "description": "Permission denied"}
            },
            "description": "Forbidden - not an admin"
        },
        404: {
            "type": "object",
            "properties": {
                "detail": {"type": "string", "description": "Vendor not found"}
            },
            "description": "Vendor not found"
        }
    }
)
class VendorApproveView(generics.UpdateAPIView):
    serializer_class = VendorApproveSerializer
    permission_classes = [IsAdmin]
    queryset = Vendor.objects.all()
    lookup_url_kwarg = 'vendor_id'

    def put(self, request, *args, **kwargs):
        vendor = self.get_object()
        serializer = self.get_serializer(vendor, data={})
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        # Notify vendor about approval
        send_mail(
            'Your Vendor Application is Approved',
            f'Congratulations! Your vendor application for {vendor.business_name} has been approved.',
            'no-reply@primersstore.com',
            [vendor.user.email]
        )

        return Response(VendorSerializer(vendor).data)


@extend_schema(
    description="Reject vendor",
    request=VendorRejectSerializer,
    responses={
        200: VendorSerializer,
        400: {
            "type": "object",
            "properties": {
                "rejection_reason": {"type": "array",  "items": {"type": "string"}, "description": "List of rejection reason errors"}
            },
             "description": "Bad request - missing rejection reason"
        },
        401: {
            "type": "object",
            "properties": {
                "detail": {"type": "string", "description": "Authentication required"}
            },
            "description": "Unauthorized"
        },
        403: {
            "type": "object",
            "properties": {
                "detail": {"type": "string", "description": "Permission denied"}
            },
            "description": "Forbidden - not an admin"
        },
        404: {
            "type": "object",
            "properties": {
                "detail": {"type": "string", "description": "Vendor not found"}
            },
            "description": "Vendor not found"
        }
    }
)
class VendorRejectView(generics.UpdateAPIView):
    serializer_class = VendorRejectSerializer
    permission_classes = [IsAdmin]
    queryset = Vendor.objects.all()
    lookup_url_kwarg = 'vendor_id'

    def put(self, request, *args, **kwargs):
        vendor = self.get_object()
        serializer = self.get_serializer(vendor, data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        # Notify vendor about rejection
        send_mail(
            'Your Vendor Application was Rejected',
            f'We regret to inform you that your vendor application for {vendor.business_name} '
            f'has been rejected.\n\nReason: {vendor.rejection_reason}',
            'no-reply@primersstore.com',
            [vendor.user.email]
        )

        return Response(VendorSerializer(vendor).data)



@extend_schema(
    description="Suspend vendor",
    request=VendorSuspendSerializer,
    responses={
        200: VendorSerializer,
        400: {"type": "object", "properties": {'detail': {"type": "string"}}},
        401: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}}
    }
)
class VendorSuspendView(generics.UpdateAPIView):
    serializer_class = VendorSuspendSerializer
    permission_classes = [IsAdmin]
    queryset = Vendor.objects.all()
    lookup_url_kwarg = 'vendor_id'

    def put(self, request, *args, **kwargs):
        vendor = self.get_object()
        serializer = self.get_serializer(vendor, data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        # Notify vendor about suspension
        send_mail(
            'Your Vendor Account was Suspended',
            f'Your vendor account for {vendor.business_name} has been suspended.\n\n'
            f'Reason: {vendor.suspension_reason}',
            'no-reply@primersstore.com',
            [vendor.user.email]
        )

        return Response(VendorSerializer(vendor).data)


@extend_schema(
    description="Ban vendor",
    request=VendorBanSerializer,
    responses={
        200: VendorSerializer,
        400: {"type": "object", "properties": {'detail': {"type": "string"}}},
        401: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}}
    }
)
class VendorBanView(generics.UpdateAPIView):
    serializer_class = VendorBanSerializer
    permission_classes = [IsAdmin]
    queryset = Vendor.objects.all()
    lookup_url_kwarg = 'vendor_id'

    def put(self, request, *args, **kwargs):
        vendor = self.get_object()
        serializer = self.get_serializer(vendor, data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        # Notify vendor about ban
        send_mail(
            'Your Vendor Account was Banned',
            f'Your vendor account for {vendor.business_name} has been banned.\n\n'
            f'Reason: {vendor.ban_reason}',
            'no-reply@primersstore.com',
            [vendor.user.email]
        )

        return Response(VendorSerializer(vendor).data)


@extend_schema(
    description="Remove vendor",
    responses={
        204: None,
        401: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}},
        500: {"type": "object", "properties": {'detail': {"type": "string"}}}
    }
)
class VendorDeleteView(generics.DestroyAPIView):
    permission_classes = [IsAdmin]
    queryset = Vendor.objects.all()
    lookup_url_kwarg = 'vendor_id'

    def delete(self, request, *args, **kwargs):
        # Get the vendor object based on vendor_id
        vendor_id = self.kwargs.get('vendor_id')
        try:
            if not Vendor.objects.filter(id=vendor_id).exists():
                return Response({'error': 'Vendor not found'}, status=status.HTTP_404_NOT_FOUND)

            vendor = Vendor.objects.get(id=vendor_id)
            vendor_email = vendor.user.email
            vendor_name = vendor.business_name

            # Perform deletion
            vendor.user.delete()
            vendor.delete()

            # Notify user about account deletion
            send_mail(
                'Your Vendor Account was Removed',
                f'Your vendor account for {vendor_name} has been removed from our system.',
                'no-reply@primersstore.com',
                [vendor_email]
            )

            return Response({'message': 'Vendor deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            print(e)
            return Response({'error': 'A server Error occured'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    description="List products for a given vendor",
    responses={
        200: ProductListSerializer(many=True),
        401: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}}
    }
)
class VendorProductsView(generics.ListAPIView):
    permission_classes = [IsVendorOrAdmin]
    lookup_url_kwarg = 'vendor_id'

    def get(self, request, *args, **kwargs):
        vendor_id = self.kwargs.get('vendor_id')
        vendor = get_object_or_404(Vendor, id=vendor_id)

        # Check if user is authorized (admin or the vendor himself)
        if not request.user.is_admin() and (not hasattr(request.user, 'vendor_profile') or
                                            request.user.vendor_profile.id != int(vendor_id)):
            return Response(
                {"detail": "You do not have permission to view this vendor's products"},
                status=status.HTTP_403_FORBIDDEN
            )

        # In a real app, you would return the vendor's products here
        # For now, we'll return a placeholder
        return Response({
            "detail": f"Products for vendor {vendor.business_name}",
            "products": []  # This would be filled with actual products
        })

@extend_schema(
    description="Create or List reviews for a specific vendor",
    responses={
        200: VendorReviewSerializer(many=True),
        201: VendorReviewSerializer,
        400: {"type": "object", "properties": {'detail': {"type": "string"}}},
        401: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}}
    }
)
class VendorReviewsView(generics.ListCreateAPIView):
    serializer_class = VendorReviewSerializer
    permission_classes = [IsAuthenticated]


    def get_queryset(self):
        vendor_id = self.kwargs['vendor_id']
        vendor = get_object_or_404(Vendor, pk=vendor_id)
        return VendorReview.objects.filter(vendor=vendor)

    def perform_create(self, serializer):
        vendor_id = self.kwargs['vendor_id']
        vendor = get_object_or_404(Vendor, pk=vendor_id)
        serializer.save(user=self.request.user, vendor=vendor)


@extend_schema(
    description="Delete a vendor review",
    responses={
        204: None,
        401: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class VendorReviewDeleteView(generics.DestroyAPIView):
    queryset = VendorReview.objects.all()
    serializer_class = VendorReviewSerializer
    permission_classes = [IsAdmin]

    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)




#Product Views
# -----------------------------------
@extend_schema(
    description="Create a product (Vendor only)",
    request=ProductCreateSerializer,
    responses={
        201: ProductCreateSerializer,
        400: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class ProductCreateView(generics.CreateAPIView):
    serializer_class = ProductCreateSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Check if user is a vendor
        if not hasattr(request.user, 'vendor_profile'):
            return Response(
                {"detail": "Only vendors can create products"},
                status=status.HTTP_403_FORBIDDEN
            )

        # Check if vendor is approved
        if request.user.vendor_profile.status != Vendor.APPROVED:
            return Response(
                {"detail": "Your vendor account must be approved to create products"},
                status=status.HTTP_403_FORBIDDEN
            )
        tags = request.data.get('tags', [])
        for tag in tags:
            Tag.objects.get_or_create(name=tag.lower())

        return super().post(request, *args, **kwargs)

    def perform_create(self, serializer):
        # Assign the vendor automatically
        serializer.save(vendor=self.request.user.vendor_profile)


@extend_schema(
    description="List/search products",
    parameters=[
        OpenApiParameter('category', OpenApiTypes.INT, description="Filter by category ID", location=OpenApiParameter.QUERY),
        OpenApiParameter('vendor', OpenApiTypes.INT, description="Filter by vendor ID", location=OpenApiParameter.QUERY),
        OpenApiParameter('tags', OpenApiTypes.STR, description="Filter by tags (comma separated)", location=OpenApiParameter.QUERY),
        OpenApiParameter('priceMin', OpenApiTypes.NUMBER, description="Minimum price", location=OpenApiParameter.QUERY),
        OpenApiParameter('priceMax', OpenApiTypes.NUMBER, description="Maximum price", location=OpenApiParameter.QUERY),
        OpenApiParameter('q', OpenApiTypes.STR, description="Search query", location=OpenApiParameter.QUERY),
    ],
    responses={
        200: ProductListSerializer(many=True),
        400: {"type": "object", "properties": {'error': {"type": "string"}}}
    }
)
class ProductListView(generics.ListAPIView):
    serializer_class = ProductListSerializer
    permission_classes = [AllowAny]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description', 'tags__name']
    ordering_fields = ['created_at', 'price', 'name']

    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        queryset = Product.objects.filter(listing_status=Product.ACTIVE).select_related('vendor', 'category').prefetch_related('tags', 'images')

        # Filter by category
        category_id = self.request.query_params.get('category')
        if category_id:
            # Get all descendant categories too
            category_ids = [int(category_id)]
            children = Category.objects.filter(category_parent__id=category_id)
            category_ids.extend([child.id for child in children])
            queryset = queryset.filter(category__id__in=category_ids)

        # Filter by vendor
        vendor_id = self.request.query_params.get('vendor')
        if vendor_id:
            queryset = queryset.filter(vendor_id=vendor_id)

        # Filter by tags
        tags = self.request.query_params.get('tags')
        if tags:
            tag_list = tags.split(',')
            for tag in tag_list:
                queryset = queryset.filter(tags__name__iexact=tag.strip())

        # Filter by price range
        price_min = self.request.query_params.get('priceMin')
        if price_min:
            queryset = queryset.filter(price__gte=Decimal(price_min))

        price_max = self.request.query_params.get('priceMax')
        if price_max:
            queryset = queryset.filter(price__lte=Decimal(price_max))

        # Search query
        q = self.request.query_params.get('q')
        if q:
            queryset = queryset.filter(
                Q(name__icontains=q) |
                Q(description__icontains=q) |
                Q(tags__name__icontains=q)
            ).distinct()

        return queryset


@extend_schema(
    description="Get product details",
    responses={
        200: ProductDetailSerializer,
        404: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}}
    }
)
class ProductDetailView(generics.RetrieveAPIView):
    serializer_class = ProductDetailSerializer
    permission_classes = [AllowAny]
    queryset = Product.objects.all().select_related('vendor', 'category').prefetch_related('tags', 'images')
    lookup_url_kwarg = 'product_id'

    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_object(self):
        obj = super().get_object()

        # If product is not active, only vendor or admin can view it
        if obj.listing_status != Product.ACTIVE:
            # Check if user is vendor owner or admin
            user = self.request.user
            if not user.is_authenticated or (
                user.role != 'admin' and
                (not hasattr(user, 'vendor_profile') or user.vendor_profile.id != obj.vendor.id)
            ):
                raise permissions.exceptions.PermissionDenied(
                    "This product is not active and can only be viewed by its owner or an admin"
                )

        return obj

@extend_schema(
    description="Update product (Vendor owner or Admin only)",
    request=ProductUpdateSerializer,
    responses={
        200: ProductUpdateSerializer,
        400: {"type": "object", "properties": {'error': {"type": "object"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}}
    }
)
class ProductUpdateView(generics.UpdateAPIView):
    serializer_class = ProductUpdateSerializer
    permission_classes = [IsAuthenticated, IsVendorOwnerOrAdmin]
    queryset = Product.objects.all()
    lookup_url_kwarg = 'product_id'

    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @extend_schema(
        description="Partially update product (Vendor owner or Admin only)",
        request=ProductUpdateSerializer,
        responses={
            200: ProductUpdateSerializer,
            400: {"type": "object", "properties": {'error': {"type": "object"}}},
            403: {"type": "object", "properties": {'detail': {"type": "string"}}},
            404: {"type": "object", "properties": {'detail': {"type": "string"}}}
        }
    )
    def patch(self, request, *args, **kwargs):
        tags = request.data.get('tags', [])
        for tag in tags:
            Tag.objects.get_or_create(name=tag.lower())
        return super().patch(request, *args, **kwargs)


@extend_schema(
    description="Delete product (Vendor owner or Admin only)",
    responses={
        204: None,
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}}
    }
)
class ProductDeleteView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated, IsVendorOwnerOrAdmin]
    queryset = Product.objects.all()
    lookup_url_kwarg = 'product_id'

    def delete(self, request, *args, **kwargs):
        product = self.get_object()

        # For soft delete, we just change the status to DISABLED
        product.listing_status = Product.DISABLED
        product.save()

        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(
    description="Create or List reviews for a specific product",
    responses={
        200: ProductReviewSerializer(many=True),
        201: ProductReviewSerializer,
        400: {"type": "object", "properties": {'detail': {"type": "string"}}},
        401: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}}
    }
)
class ProductReviewsView(generics.ListCreateAPIView):
    serializer_class = ProductReviewSerializer

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        if self.request.method == 'GET':
            permission_classes = [AllowAny]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def get_queryset(self):
        product_id = self.kwargs['product_id']
        product = get_object_or_404(Product, pk=product_id)
        return ProductReview.objects.filter(product=product)

    def perform_create(self, serializer):
        product_id = self.kwargs['product_id']
        product = get_object_or_404(Product, pk=product_id)
        serializer.save(user=self.request.user, product=product)

@extend_schema(
    description="Delete a product review",
    responses={
        204: None,
        401: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class ProductReviewDeleteView(generics.DestroyAPIView):
    queryset = ProductReview.objects.all()
    serializer_class = ProductReviewSerializer
    permission_classes = [IsAdmin]

    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)


#Categories Views
@extend_schema(
    description="Create or List categories",
    responses={
        200: CategorySerializer(many=True),
        201: CategorySerializer,
        400: {"type": "object", "properties": {'detail': {"type": "string"}}},
        401: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class CategoryListCreateView(generics.ListCreateAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [AllowAny]

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        if self.request.method == 'GET':
            permission_classes = [AllowAny]
        else:
            permission_classes = [IsAdmin]
        return [permission() for permission in permission_classes]

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

@extend_schema(
    description="Get category details",
    responses={
        200: CategorySerializer,
        404: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class CategoryDetailView(generics.RetrieveAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

@extend_schema(
    description="Update category details",
    request=CategorySerializer,
    responses={
        200: CategorySerializer,
        400: {"type": "object", "properties": {'detail': {"type": "string"}}},
        401: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class CategoryUpdateView(generics.UpdateAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [IsAdmin]

    def put(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)

    def patch(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)

@extend_schema(
    description="Delete a category",
    responses={
        204: None,
        401: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class CategoryDeleteView(generics.DestroyAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [IsAdmin]

    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)

@extend_schema(
    description="Create or List tags",
    responses={
        200: TagSerializer(many=True),
        201: TagSerializer,
        400: {"type": "object", "properties": {'detail': {"type": "string"}}},
        401: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class TagListCreateView(generics.ListCreateAPIView):
    queryset = Tag.objects.all()
    serializer_class = TagSerializer
    permission_classes = [IsAdmin]

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        if self.request.method == 'GET':
            permission_classes = [AllowAny]
        else:
            permission_classes = [IsAdmin]
        return [permission() for permission in permission_classes]

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

@extend_schema(
    description="Get tag details",
    responses={
        200: TagSerializer,
        404: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class TagDetailView(generics.RetrieveAPIView):
    queryset = Tag.objects.all()
    serializer_class = TagSerializer
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

@extend_schema(
    description="Update tag details",
    request=TagSerializer,
    responses={
        200: TagSerializer,
        400: {"type": "object", "properties": {'detail': {"type": "string"}}},
        401: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class TagUpdateView(generics.RetrieveUpdateAPIView):
    queryset = Tag.objects.all()
    serializer_class = TagSerializer
    permission_classes = [IsAdmin]

    def put(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)

    def patch(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)

@extend_schema(
    description="Delete a tag",
    responses={
        204: None,
        401: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class TagDeleteView(generics.DestroyAPIView):
    queryset = Tag.objects.all()
    serializer_class = TagSerializer
    permission_classes = [IsAdmin]

    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)


@extend_schema(
    description="Get current user’s cart items",
    responses={
        200: CartSerializer,
        401: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class CartView(generics.RetrieveAPIView):
    """
    GET /api/cart: Get current user’s cart items
    Roles: Customer
    """
    serializer_class = CartSerializer
    permission_classes = [IsCustomer]

    def get_object(self):
        # Ensure a cart exists for the user. If not, create one.
        cart, created = Cart.objects.get_or_create(user=self.request.user)
        return cart

@extend_schema(
    description="Add product to cart",
    request=AddCartItemSerializer,
    responses={
        201: CartItemSerializer,
        400: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class CartAddItemView(generics.CreateAPIView):
    """
    POST /api/cart/add: Add product to cart (`productId`, `qty`)
    Roles: Customer
    """
    serializer_class = AddCartItemSerializer
    permission_classes = [IsCustomer]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Get arguments
        user = request.user
        product_id = serializer.validated_data['product_id']
        quantity = serializer.validated_data['quantity']
        cart, created = Cart.objects.get_or_create(user=user)
        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            return Response({"error": "Product not found."}, status=status.HTTP_404_NOT_FOUND)


        # Check if quantity exceeds stock
        if product.stock_quantity < quantity:
            return Response(
                {'quantity': f'Only {product.stock_quantity} units of {product.name} are available.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        cart_item, item_created = CartItem.objects.get_or_create(cart=cart, product=product, defaults={'quantity': quantity})

        if not item_created:
            # If item already in cart, update quantity
            new_quantity = cart_item.quantity + quantity
            if product.stock_quantity < new_quantity:
                return Response(
                    {"quantity": f"Adding {quantity} units would exceed available stock. Only {product.stock_quantity - cart_item.quantity} more units can be added."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            cart_item.quantity = new_quantity
            cart_item.save()

        # Return the updated cart item
        cart_item_serializer = CartItemSerializer(cart_item)
        return Response(cart_item_serializer.data, status=status.HTTP_201_CREATED)

@extend_schema(
    description="Update cart item quantity",
    request=UpdateCartItemSerializer,
    responses={
        200: CartItemSerializer,
        400: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class CartUpdateItemView(generics.UpdateAPIView):
    """
    PUT /api/cart/update/:itemId: Update cart item quantity
    Roles: Customer
    """
    queryset = CartItem.objects.all()
    serializer_class = UpdateCartItemSerializer
    permission_classes = [IsCustomer]
    lookup_field = 'id'
    lookup_url_kwarg = 'itemId'

    def get_queryset(self):
        user = self.request.user
        cart = get_object_or_404(Cart, user=user)
        return self.queryset.filter(cart=cart)

    def put(self, request, *args, **kwargs):
        cart_item = self.get_object()
        serializer = self.get_serializer(cart_item, data=request.data)
        serializer.is_valid(raise_exception=True)

        product = cart_item.product
        new_quantity = serializer.validated_data.get('quantity', cart_item.quantity)

        # Check if product is in stock for the new quantity
        if product.stock_quantity < new_quantity:
            return Response(
                {'quantity': f'Only {product.stock_quantity} units of {product.name} are available.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer.save()

        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        cart_item = self.get_object()
        serializer = self.get_serializer(cart_item, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        product = cart_item.product
        new_quantity = serializer.validated_data.get('quantity', cart_item.quantity)

        # Check if product is in stock for the new quantity
        if product.stock_quantity < new_quantity:
            return Response(
                {'quantity': f'Only {product.stock_quantity} units of {product.name} are available.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer.save()
        return Response(serializer.data)

@extend_schema(
    description="Remove item from cart",
    responses={
        204: None,
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class CartRemoveItemView(generics.DestroyAPIView):
    """
    DELETE /api/cart/remove/:itemId: Remove item from cart
    Roles: Customer
    """
    queryset = CartItem.objects.all()
    permission_classes = [IsCustomer]
    lookup_field = 'id'
    lookup_url_kwarg = 'itemId'

    def get_queryset(self):
        user = self.request.user
        cart = get_object_or_404(Cart, user=user)
        return self.queryset.filter(cart=cart)

@extend_schema(
    description="Get wishlist",
    responses={
        200: WishlistSerializer,
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class WishlistView(generics.RetrieveAPIView):
    """
    GET /api/wishlist: Get wishlist
    Roles: Customer
    """
    serializer_class = WishlistSerializer
    permission_classes = [IsCustomer]

    def get_object(self):
        # Ensure a wishlist exists for the user. If not, create one.
        wishlist, created = Wishlist.objects.get_or_create(user=self.request.user)
        return wishlist

@extend_schema(
    description="Add product to wishlist",
    responses={
        201: WishlistItemSerializer,
        400: {"type": "object", "properties": {'detail': {"type": "string"}}},
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class WishlistAddItemView(generics.CreateAPIView):
    """
    POST /api/wishlist/:productId: Add product to wishlist
    Roles: Customer
    """
    serializer_class = WishlistItemSerializer
    permission_classes = [IsCustomer]

    def create(self, request, *args, **kwargs):
        user = request.user
        product_id = self.kwargs.get('productId')

        wishlist, created = Wishlist.objects.get_or_create(user=user)
        product = get_object_or_404(Product, id=product_id)
        # Check if product is out of stock
        if product.stock_quantity <= 0:
            return Response({'detail': 'Product is out of stock.'}, status=status.HTTP_400_BAD_REQUEST)
        # Check if the product is already in the wishlist
        if WishlistItem.objects.filter(wishlist=wishlist, product=product).exists():
            return Response({'detail': 'Product already in wishlist.'}, status=status.HTTP_400_BAD_REQUEST)

        wishlist_item = WishlistItem.objects.create(wishlist=wishlist, product=product)
        serializer = self.get_serializer(wishlist_item)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

@extend_schema(
    description="Remove from wishlist",
    responses={
        204: None,
        403: {"type": "object", "properties": {'detail': {"type": "string"}}},
        404: {"type": "object", "properties": {'detail': {"type": "string"}}},
    }
)
class WishlistRemoveItemView(generics.DestroyAPIView):
    """
    DELETE /api/wishlist/:productId: Remove from wishlist
    Roles: Customer
    """
    queryset = WishlistItem.objects.all()
    permission_classes = [ IsCustomer]
    lookup_field = 'product_id' # We'll use product_id for removal

    def get_queryset(self):
        user = self.request.user
        wishlist = get_object_or_404(Wishlist, user=user)
        return self.queryset.filter(wishlist=wishlist)

    def get_object(self):
        # Override get_object to filter by product_id and wishlist
        queryset = self.get_queryset()
        filter_kwargs = {self.lookup_field: self.kwargs[self.lookup_url_kwarg]}
        obj = get_object_or_404(queryset, **filter_kwargs)
        return obj

    lookup_url_kwarg = 'productId'


class CartOrderCreateView(generics.CreateAPIView):
    """
    POST /api/cart/place-order/: Place an order from items in the cart
    Roles: Customer
    """
    serializer_class = CartOrderSerializer

    permission_classes = [IsCustomer]

    def perform_create(self, serializer):
        # Get the user's cart
        cart = get_object_or_404(Cart, user=self.request.user)
        cart_items = CartItem.objects.filter(cart=cart)
        shipping_address = self.request.data.get('shipping_address')
        recipient_name = self.request.data.get('recipient_name')
        serializer.is_valid(raise_exception=True)
        if not cart_items.exists():
            raise serializers.ValidationError("Your cart is empty.")

        # Calculate the total order amount


        # Create order items from the cart items
        for cart_item in cart_items:
            Order.objects.create(
                shipping_address=shipping_address,
                recipient_name=recipient_name,
                product=cart_item.product,
                quantity=cart_item.quantity,
                price=cart_item.product.price
            )
            # Reduce stock quantity
            product = cart_item.product
            product.stock_quantity -= cart_item.quantity
            product.save()

        # Clear the cart
        cart_items.delete()

class OrderListCreateView(generics.ListCreateAPIView):
    """
    POST /api/orders: Place an order (checkout)
    GET /api/orders: List user’s past orders
    Roles: Customer
    """
    serializer_class = OrderSerializer
    permission_classes = [IsCustomer]

    def get_queryset(self):
        # List orders only for the current user
        return Order.objects.filter(user=self.request.user)

    def perform_create(self, serializer):

        # Save the current user as the order's user
        serializer.save(user=self.request.user,context={'request': self.request})


class OrderDetailView(generics.RetrieveAPIView):
    """
    GET /api/orders/:orderId: Get order details/track shipping
    Roles: Customer, Admin, Vendor (own)
    """
    serializer_class = OrderSerializer
    permission_classes=[IsAdmin | IsOwnerOfOrder]
    queryset = Order.objects.all()


class OrderStatusUpdateView(generics.UpdateAPIView):
    """
    PUT /api/orders/:orderId/status: Update order status (e.g., shipped)
    Roles: Admin, Vendor (own)
    """
    serializer_class = OrderStatusUpdateSerializer
    queryset = Order.objects.all()
