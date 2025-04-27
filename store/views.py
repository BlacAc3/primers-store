from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from rest_framework import generics, status, permissions, filters
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenRefreshView
# from rest_framework_simplejwt.tokens import RefreshToken
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .serializers import (
    RegisterSerializer, LoginSerializer, LogoutSerializer,
    UserSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer,
    VendorRegistrationSerializer, VendorSerializer, VendorStatusUpdateSerializer,
    VendorApproveSerializer, VendorRejectSerializer, VendorSuspendSerializer, VendorBanSerializer
)

from .models import Vendor
from .permissions import IsAdmin, IsVendorOrAdmin

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
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="Register a new user",
        responses={
            201: RegisterSerializer,
            400: "Bad request - user already exists"
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
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="Login and obtain JWT token",
        responses={200: openapi.Response('Login successful', LoginSerializer)}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)

class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Logout and invalidate JWT token",
        responses={204: "No content"}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

class MeView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get current user details",
        responses={200: UserSerializer}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_object(self):
        return self.request.user

class RefreshTokenView(TokenRefreshView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Refresh JWT token",
        responses={200: "New token pair"}
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

class PasswordResetView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="Request password reset email",
        responses={200: openapi.Response('Email sent if account exists',
                    schema=openapi.Schema(type=openapi.TYPE_OBJECT,
                    properties={'detail': openapi.Schema(type=openapi.TYPE_STRING)}))}
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
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="Confirm password reset with token",
        responses={
            200: openapi.Response('Password reset successful',
                    schema=openapi.Schema(type=openapi.TYPE_OBJECT,
                    properties={'detail': openapi.Schema(type=openapi.TYPE_STRING)})),
            400: openapi.Response('Invalid token',
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
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="Submit vendor registration request",
        responses={201: VendorRegistrationSerializer}
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
    permission_classes = [permissions.IsAdminUser]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['business_name', 'user__username', 'user__email']
    ordering_fields = ['created_at', 'business_name', 'status']

    @swagger_auto_schema(
        operation_description="List all vendors (with status filter)",
        manual_parameters=[
            openapi.Parameter('status', openapi.IN_QUERY, description="Filter by vendor status",
                             type=openapi.TYPE_STRING,
                             enum=[status[0] for status in Vendor.STATUS_CHOICES])
        ]
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
        operation_description="Get vendor details"
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class VendorApproveView(generics.UpdateAPIView):
    serializer_class = VendorApproveSerializer
    permission_classes = [IsAdmin]
    queryset = Vendor.objects.all()
    lookup_url_kwarg = 'vendor_id'

    @swagger_auto_schema(
        operation_description="Approve vendor"
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
        operation_description="Reject vendor"
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
        operation_description="Suspend vendor"
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
        operation_description="Ban vendor"
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
        operation_description="Remove vendor"
    )
    def destroy(self, request, *args, **kwargs):
        vendor = self.get_object()
        vendor_email = vendor.user.email
        vendor_name = vendor.business_name

        # Perform deletion
        response = super().destroy(request, *args, **kwargs)

        # Notify user about account deletion
        send_mail(
            'Your Vendor Account was Removed',
            f'Your vendor account for {vendor_name} has been removed from our system.',
            'no-reply@primersstore.com',
            [vendor_email]
        )

        return response

class VendorProductsView(generics.ListAPIView):
    permission_classes = [IsVendorOrAdmin]
    lookup_url_kwarg = 'vendor_id'

    @swagger_auto_schema(
        operation_description="List products for a given vendor"
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
