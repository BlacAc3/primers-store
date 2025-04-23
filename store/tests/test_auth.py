# import json
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework import status
from rest_framework.test import APIClient

from store.models import CustomUser


class AuthenticationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('auth-register')
        self.login_url = reverse('auth-login')
        self.logout_url = reverse('auth-logout')
        self.me_url = reverse('auth-me')
        self.refresh_url = reverse('token-refresh')
        self.password_reset_url = reverse('password-reset')
        self.password_reset_confirm_url = reverse('password-reset-confirm')

        # Create test user
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpassword123',
            'role': 'customer'
        }
        self.user = CustomUser.objects.create_user(
            username=self.user_data['username'],
            email=self.user_data['email'],
            password=self.user_data['password'],
            role=self.user_data['role']
        )

        # Vendor account
        self.vendor_data = {
            'username': 'testvendor',
            'email': 'vendor@example.com',
            'password': 'vendorpass123',
            'role': 'vendor'
        }
        self.vendor = CustomUser.objects.create_user(
            username=self.vendor_data['username'],
            email=self.vendor_data['email'],
            password=self.vendor_data['password'],
            role=self.vendor_data['role']
        )

    def test_user_registration(self):
        """Test user registration with valid data"""
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'newuserpass123',
            'role': 'customer'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(CustomUser.objects.filter(username='newuser').exists())
        user = CustomUser.objects.get(username='newuser')
        self.assertEqual(user.role, 'customer')

    def test_vendor_registration(self):
        """Test vendor registration"""
        data = {
            'username': 'newvendor',
            'email': 'newvendor@example.com',
            'password': 'newvendorpass123',
            'role': 'vendor'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(CustomUser.objects.filter(username='newvendor').exists())
        user = CustomUser.objects.get(username='newvendor')
        self.assertEqual(user.role, 'vendor')
        self.assertTrue(user.is_vendor())

    def test_duplicate_username_registration(self):
        """Test registration with existing username fails"""
        data = {
            'username': 'testuser',  # Existing username
            'email': 'another@example.com',
            'password': 'testpass123',
            'role': 'customer'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_role_registration(self):
        """Test registration with invalid role fails"""
        data = {
            'username': 'invalidrole',
            'email': 'invalid@example.com',
            'password': 'testpass123',
            'role': 'invalid_role'  # Invalid role
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_success(self):
        """Test successful user login"""
        data = {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials fails"""
        data = {
            'email': self.user_data['email'],
            'password': 'wrongpassword'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout(self):
        """Test user logout"""
        # First login to get the refresh token
        login_data = {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        }
        login_response = self.client.post(self.login_url, login_data, format='json')
        refresh_token = login_response.data['refresh']

        # Set up authenticated client
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {login_response.data["access"]}')

        # Test logout
        logout_data = {'refresh': refresh_token}
        response = self.client.post(self.logout_url, logout_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Verify we can't use the refresh token anymore (would require token blacklist to be set up)
        # This part is usually tested with more advanced setup including blacklist

    def test_me_authenticated(self):
        """Test retrieving authenticated user info"""
        # Login first
        login_data = {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        }
        login_response = self.client.post(self.login_url, login_data, format='json')

        # Set authentication token
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {login_response.data["access"]}')

        # Test /me endpoint
        response = self.client.get(self.me_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], self.user_data['username'])
        self.assertEqual(response.data['email'], self.user_data['email'])
        self.assertEqual(response.data['role'], self.user_data['role'])

    def test_me_unauthenticated(self):
        """Test that unauthenticated users can't access /me"""
        response = self.client.get(self.me_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_password_reset_request(self):
        """Test password reset request"""
        data = {'email': self.user_data['email']}
        response = self.client.post(self.password_reset_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('detail', response.data)

    def test_password_reset_nonexistent_email(self):
        """Test password reset with nonexistent email still returns 200 for security"""
        data = {'email': 'nonexistent@example.com'}
        response = self.client.post(self.password_reset_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_password_reset_confirm(self):
        """Test password reset confirmation"""
        # Generate reset token
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = PasswordResetTokenGenerator().make_token(self.user)

        # Test with valid data
        data = {
            'uid': uid,
            'token': token,
            'new_password': 'newpassword123'
        }
        response = self.client.post(self.password_reset_confirm_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify password was actually changed
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpassword123'))

    def test_password_reset_confirm_invalid_token(self):
        """Test password reset confirmation with invalid token"""
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))

        # Test with invalid token
        data = {
            'uid': uid,
            'token': 'invalid-token',
            'new_password': 'newpassword123'
        }
        response = self.client.post(self.password_reset_confirm_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Verify password was not changed
        self.user.refresh_from_db()
        self.assertFalse(self.user.check_password('newpassword123'))
        self.assertTrue(self.user.check_password(self.user_data['password']))

    def test_token_refresh(self):
        """Test refreshing access token"""
        # First login to get the refresh token
        login_data = {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        }
        login_response = self.client.post(self.login_url, login_data, format='json')
        refresh_token = login_response.data['refresh']

        # Set authentication header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {login_response.data["access"]}')

        # Test refresh endpoint
        refresh_data = {'refresh': refresh_token}
        response = self.client.post(self.refresh_url, refresh_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
