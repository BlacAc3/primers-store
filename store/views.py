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
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .serializers import (
    ProductCreateSerializer, ProductListSerializer, ProductUpdateSerializer, RegisterSerializer, LoginSerializer, LogoutSerializer,
    UserSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer,
    VendorRegistrationSerializer, VendorSerializer,
    VendorApproveSerializer, VendorRejectSerializer, VendorSuspendSerializer, VendorBanSerializer,
    ProductCreateSerializer, ProductListSerializer, ProductDetailSerializer,ProductUpdateSerializer
)

from .models import Vendor, Product, Category, Tag
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

class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Register a new user",
        request_body=RegisterSerializer,
        responses={
            201: openapi.Response('Created', RegisterSerializer),
            400: openapi.Response('Bad Request', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING)
                }
            ))
        }
    )
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

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Login and obtain JWT token",
        request_body=LoginSerializer,
        responses={
            200: openapi.Response('Login successful', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                    'access': openapi.Schema(type=openapi.TYPE_STRING),
                    'user': openapi.Schema(type=openapi.TYPE_OBJECT)
                }
            )),
            400: "Bad request - invalid credentials"
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)

class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Logout and invalidate JWT token",
        request_body=LogoutSerializer,
        responses={
            204: "No content - logout successful",
            400: "Bad request - invalid token"
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

class MeView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get current user details",
        responses={
            200: UserSerializer,
            401: "Unauthorized - not authenticated"
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_object(self):
        return self.request.user

class RefreshTokenView(TokenRefreshView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Refresh JWT token",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['refresh'],
            properties={
                'refresh': openapi.Schema(type=openapi.TYPE_STRING)
            }
        ),
        responses={
            200: openapi.Response('New token pair', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'access': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
            401: "Unauthorized - invalid refresh token"
        }
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

class PasswordResetView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Request password reset email",
        request_body=PasswordResetSerializer,
        responses={
            200: openapi.Response('Email sent if account exists',
                    schema=openapi.Schema(type=openapi.TYPE_OBJECT,
                    properties={'detail': openapi.Schema(type=openapi.TYPE_STRING)})),
            400: "Bad request - invalid email format"
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.filter(email=serializer.validated_data['email']).first()
        if user:
            send_reset_email(user, request)
        return Response({'detail': 'If email exists, reset link sent.'}, status=status.HTTP_200_OK)

class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Confirm password reset with token",
        request_body=PasswordResetConfirmSerializer,
        responses={
            200: openapi.Response('Password reset successful',
                    schema=openapi.Schema(type=openapi.TYPE_OBJECT,
                    properties={'detail': openapi.Schema(type=openapi.TYPE_STRING)})),
            400: openapi.Response('Invalid token or password',
                    schema=openapi.Schema(type=openapi.TYPE_OBJECT,
                    properties={'error': openapi.Schema(type=openapi.TYPE_STRING)}))
        }
    )
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


class VendorRegistrationView(generics.CreateAPIView):
    serializer_class = VendorRegistrationSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Submit vendor registration request",
        request_body=VendorRegistrationSerializer,
        responses={
            201: VendorRegistrationSerializer,
            400: "Bad request - invalid data"
        }
    )
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


class VendorListView(generics.ListAPIView):
    serializer_class = VendorSerializer
    permission_classes = [IsAdmin]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['business_name', 'user__username', 'user__email']
    ordering_fields = ['created_at', 'business_name', 'status']

    @swagger_auto_schema(
        operation_description="List all vendors (with status filter)",
        manual_parameters=[
            openapi.Parameter('status', openapi.IN_QUERY, description="Filter by vendor status",
                             type=openapi.TYPE_STRING,
                             enum=[status[0] for status in Vendor.STATUS_CHOICES])
        ],
        responses={
            200: openapi.Response('List of vendors', VendorSerializer(many=True)),
            401: "Unauthorized",
            403: "Forbidden - not an admin"
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        queryset = Vendor.objects.all().select_related('user')
        status = self.request.query_params.get('status')
        if status:
            queryset = queryset.filter(status=status)
        return queryset


class VendorDetailView(generics.RetrieveAPIView):
    serializer_class = VendorSerializer
    permission_classes = [IsAdmin]
    queryset = Vendor.objects.all().select_related('user')
    lookup_url_kwarg = 'vendor_id'

    @swagger_auto_schema(
        operation_description="Get vendor details",
        responses={
            200: VendorSerializer,
            401: "Unauthorized",
            403: "Forbidden - not an admin",
            404: "Vendor not found"
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class VendorApproveView(generics.UpdateAPIView):
    serializer_class = VendorApproveSerializer
    permission_classes = [IsAdmin]
    queryset = Vendor.objects.all()
    lookup_url_kwarg = 'vendor_id'

    @swagger_auto_schema(
        operation_description="Approve vendor",
        request_body=openapi.Schema(type=openapi.TYPE_OBJECT, properties={}),
        responses={
            200: VendorSerializer,
            401: "Unauthorized",
            403: "Forbidden - not an admin",
            404: "Vendor not found"
        }
    )
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


class VendorRejectView(generics.UpdateAPIView):
    serializer_class = VendorRejectSerializer
    permission_classes = [IsAdmin]
    queryset = Vendor.objects.all()
    lookup_url_kwarg = 'vendor_id'

    @swagger_auto_schema(
        operation_description="Reject vendor",
        request_body=VendorRejectSerializer,
        responses={
            200: VendorSerializer,
            400: "Bad request - missing rejection reason",
            401: "Unauthorized",
            403: "Forbidden - not an admin",
            404: "Vendor not found"
        }
    )
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


class VendorSuspendView(generics.UpdateAPIView):
    serializer_class = VendorSuspendSerializer
    permission_classes = [IsAdmin]
    queryset = Vendor.objects.all()
    lookup_url_kwarg = 'vendor_id'

    @swagger_auto_schema(
        operation_description="Suspend vendor",
        request_body=VendorSuspendSerializer,
        responses={
            200: VendorSerializer,
            400: "Bad request - missing suspension reason",
            401: "Unauthorized",
            403: "Forbidden - not an admin",
            404: "Vendor not found"
        }
    )
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


class VendorBanView(generics.UpdateAPIView):
    serializer_class = VendorBanSerializer
    permission_classes = [IsAdmin]
    queryset = Vendor.objects.all()
    lookup_url_kwarg = 'vendor_id'

    @swagger_auto_schema(
        operation_description="Ban vendor",
        request_body=VendorBanSerializer,
        responses={
            200: VendorSerializer,
            400: "Bad request - missing ban reason",
            401: "Unauthorized",
            403: "Forbidden - not an admin",
            404: "Vendor not found"
        }
    )
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


class VendorDeleteView(generics.DestroyAPIView):
    permission_classes = [IsAdmin]
    queryset = Vendor.objects.all()
    lookup_url_kwarg = 'vendor_id'

    @swagger_auto_schema(
        operation_description="Remove vendor",
        responses={
            204: openapi.Response(
                description="Vendor successfully deleted",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="Success message"
                        )
                    }
                )
            ),
            401: "Unauthorized",
            403: "Forbidden - not an admin",
            404: "Vendor not found",
            500: "Server error"
        }
    )
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

class VendorProductsView(generics.ListAPIView):
    permission_classes = [IsVendorOrAdmin]
    lookup_url_kwarg = 'vendor_id'

    @swagger_auto_schema(
        operation_description="List products for a given vendor",
        responses={
            200: openapi.Response('Products for this vendor', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING),
                    'products': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT))
                }
            )),
            401: "Unauthorized",
            403: "Forbidden - not authorized to view these products",
            404: "Vendor not found"
        }
    )
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

class ProductCreateView(generics.CreateAPIView):
    serializer_class = ProductCreateSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Create a new product (Vendor only)",
        request_body=ProductCreateSerializer,
        responses={
            201: openapi.Response('Created', ProductCreateSerializer),
            400: openapi.Response('Bad Request', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )),
            403: openapi.Response('Forbidden', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            ))
        }
    )
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


class ProductListView(generics.ListAPIView):
    serializer_class = ProductListSerializer
    permission_classes = [AllowAny]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description', 'tags__name']
    ordering_fields = ['created_at', 'price', 'name']

    @swagger_auto_schema(
        operation_description="List/search products",
        manual_parameters=[
            openapi.Parameter('category', openapi.IN_QUERY,
                             description="Filter by category ID",
                             type=openapi.TYPE_INTEGER),
            openapi.Parameter('vendor', openapi.IN_QUERY,
                             description="Filter by vendor ID",
                             type=openapi.TYPE_INTEGER),
            openapi.Parameter('tags', openapi.IN_QUERY,
                             description="Filter by tags (comma separated)",
                             type=openapi.TYPE_STRING),
            openapi.Parameter('priceMin', openapi.IN_QUERY,
                             description="Minimum price",
                             type=openapi.TYPE_NUMBER),
            openapi.Parameter('priceMax', openapi.IN_QUERY,
                             description="Maximum price",
                             type=openapi.TYPE_NUMBER),
            openapi.Parameter('q', openapi.IN_QUERY,
                             description="Search query",
                             type=openapi.TYPE_STRING),
        ],
        responses={
            200: openapi.Response('Success', ProductListSerializer(many=True)),
            400: openapi.Response('Bad Request', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING)
                }
            ))
        }
    )
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


class ProductDetailView(generics.RetrieveAPIView):
    serializer_class = ProductDetailSerializer
    permission_classes = [AllowAny]
    queryset = Product.objects.all().select_related('vendor', 'category').prefetch_related('tags', 'images')
    lookup_url_kwarg = 'product_id'

    @swagger_auto_schema(
        operation_description="Get product details",
        responses={
            200: openapi.Response('Success', ProductDetailSerializer),
            404: openapi.Response('Not Found', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )),
            403: openapi.Response('Forbidden', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            ))
        }
    )
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


class ProductUpdateView(generics.UpdateAPIView):
    serializer_class = ProductUpdateSerializer
    permission_classes = [IsAuthenticated, IsVendorOwnerOrAdmin]
    queryset = Product.objects.all()
    lookup_url_kwarg = 'product_id'

    @swagger_auto_schema(
        operation_description="Update product (Vendor owner or Admin only)",
        request_body=ProductUpdateSerializer,
        responses={
            200: openapi.Response('Success', ProductUpdateSerializer),
            400: openapi.Response('Bad Request', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_OBJECT)
                }
            )),
            403: openapi.Response('Forbidden', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )),
            404: openapi.Response('Not Found', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            ))
        }
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Partially update product (Vendor owner or Admin only)",
        request_body=ProductUpdateSerializer,
        responses={
            200: openapi.Response('Success', ProductUpdateSerializer),
            400: openapi.Response('Bad Request', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_OBJECT)
                }
            )),
            403: openapi.Response('Forbidden', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )),
            404: openapi.Response('Not Found', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            ))
        }
    )
    def patch(self, request, *args, **kwargs):
        tags = request.data.get('tags', [])
        for tag in tags:
            Tag.objects.get_or_create(name=tag.lower())
        return super().patch(request, *args, **kwargs)


class ProductDeleteView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated, IsVendorOwnerOrAdmin]
    queryset = Product.objects.all()
    lookup_url_kwarg = 'product_id'

    @swagger_auto_schema(
        operation_description="Delete product (Vendor owner or Admin only)",
        responses={
            204: openapi.Response('No Content', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={}
            )),
            403: openapi.Response('Forbidden', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )),
            404: openapi.Response('Not Found', schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            ))
        }
    )
    def delete(self, request, *args, **kwargs):
        product = self.get_object()

        # For soft delete, we just change the status to DISABLED
        product.status = Product.DISABLED
        product.save()

        return Response(status=status.HTTP_204_NO_CONTENT)

    # If you want hard delete instead, uncomment this and comment the delete method above
    # def perform_destroy(self, instance):
    #     instance.delete()
