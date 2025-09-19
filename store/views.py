from decimal import Decimal
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from django.db.models import Q

from rest_framework import generics, status, filters, permissions
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
)

from .models import Vendor, Product, Category, Tag, VendorReview, ProductReview
from .permissions import IsAdmin, IsVendorOrAdmin, AllowAny, IsAuthenticated, IsVendorOwnerOrAdmin

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
        queryset = Product.objects.filter(status=Product.ACTIVE).select_related('vendor', 'category').prefetch_related('tags', 'images')

        # Filter by category
        category_id = self.request.query_params.get('category')
        if category_id:
            # Get all descendant categories too
            category_ids = [int(category_id)]
            children = Category.objects.filter(parent_id=category_id)
            category_ids.extend([child.id for child in children])
            queryset = queryset.filter(category_id__in=category_ids)

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
        if obj.status != Product.ACTIVE:
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
        product.status = Product.DISABLED
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
