from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from store.models import CustomUser, Vendor


class VendorManagementTests(TestCase):
    def setUp(self):
        self.client = APIClient()

        # Create admin user
        self.admin_data = {
            'username': 'admin',
            'email': 'admin@example.com',
            'password': 'adminpass123',
            'role': 'admin'
        }
        self.admin = CustomUser.objects.create_user(
            username=self.admin_data['username'],
            email=self.admin_data['email'],
            password=self.admin_data['password'],
            role=self.admin_data['role']
        )

        # Create customer user
        self.customer_data = {
            'username': 'customer',
            'email': 'customer@example.com',
            'password': 'customerpass123',
            'role': 'customer'
        }
        self.customer = CustomUser.objects.create_user(
            username=self.customer_data['username'],
            email=self.customer_data['email'],
            password=self.customer_data['password'],
            role=self.customer_data['role']
        )

        # Create pending vendor user
        self.vendor_data = {
            'username': 'vendor',
            'email': 'vendor@example.com',
            'password': 'vendorpass123',
            'role': 'vendor'
        }
        self.vendor_user = CustomUser.objects.create_user(
            username=self.vendor_data['username'],
            email=self.vendor_data['email'],
            password=self.vendor_data['password'],
            role=self.vendor_data['role']
        )

        # Create vendor profile
        self.vendor = Vendor.objects.create(
            user=self.vendor_user,
            business_name="Test Vendor Business",
            business_description="This is a test vendor business",
            website="https://testvendor.com",
            status=Vendor.PENDING
        )

        # Create approved vendor
        self.approved_vendor_data = {
            'username': 'approvedvendor',
            'email': 'approved@example.com',
            'password': 'approvedpass123',
            'role': 'vendor'
        }
        self.approved_vendor_user = CustomUser.objects.create_user(
            username=self.approved_vendor_data['username'],
            email=self.approved_vendor_data['email'],
            password=self.approved_vendor_data['password'],
            role=self.approved_vendor_data['role']
        )

        self.approved_vendor = Vendor.objects.create(
            user=self.approved_vendor_user,
            business_name="Approved Vendor Business",
            business_description="This is an approved vendor business",
            website="https://approvedvendor.com",
            status=Vendor.APPROVED
        )

        # Endpoint URLs
        self.vendor_register_url = reverse('vendor-register')
        self.vendor_list_url = reverse('vendor-list')
        self.vendor_detail_url = lambda vendor_id: reverse('vendor-detail', args=[vendor_id])
        self.vendor_approve_url = lambda vendor_id: reverse('vendor-approve', args=[vendor_id])
        self.vendor_reject_url = lambda vendor_id: reverse('vendor-reject', args=[vendor_id])
        self.vendor_suspend_url = lambda vendor_id: reverse('vendor-suspend', args=[vendor_id])
        self.vendor_ban_url = lambda vendor_id: reverse('vendor-ban', args=[vendor_id])
        self.vendor_delete_url = lambda vendor_id: reverse('vendor-delete', args=[vendor_id])
        self.vendor_products_url = lambda vendor_id: reverse('vendor-products', args=[vendor_id])

        # Login URLs
        self.login_url = reverse('auth-login')

    def get_auth_token(self, user_data):
        """Helper method to get auth token for a user"""
        login_data = {
            'email': user_data['email'],
            'password': user_data['password']
        }
        response = self.client.post(self.login_url, login_data, format='json')
        return response.data['access']

    def test_vendor_registration(self):
        """Test vendor registration with valid data"""
        data = {
            'user': {
                'username': 'newvendor',
                'email': 'newvendor@example.com',
                'password': 'newvendorpass123',
                'role': 'vendor'
            },
            'business_name': 'New Vendor Business',
            'business_description': 'This is a new vendor business',
            'website': 'https://newvendor.com'
        }
        response = self.client.post(self.vendor_register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(CustomUser.objects.filter(username='newvendor').exists())

        # Verify vendor was created with pending status
        user = CustomUser.objects.get(username='newvendor')
        self.assertEqual(user.role, 'vendor')
        self.assertTrue(hasattr(user, 'vendor_profile'))
        self.assertEqual(user.vendor_profile.status, Vendor.PENDING)
        self.assertEqual(user.vendor_profile.business_name, 'New Vendor Business')

    def test_vendor_registration_validation(self):
        """Test vendor registration validation"""
        # Missing business name
        data = {
            'user': {
                'username': 'newvendor',
                'email': 'newvendor@example.com',
                'password': 'newvendorpass123',
                'role': 'vendor'
            },
            'business_description': 'This is a new vendor business',
            'website': 'https://newvendor.com'
        }
        response = self.client.post(self.vendor_register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Invalid user data (missing email)
        data = {
            'user': {
                'username': 'newvendor',
                'password': 'newvendorpass123',
                'role': 'vendor'
            },
            'business_name': 'New Vendor Business',
            'business_description': 'This is a new vendor business',
            'website': 'https://newvendor.com'
        }
        response = self.client.post(self.vendor_register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_list_vendors_admin(self):
        """Test listing vendors as admin"""
        # Authenticate as admin
        token = self.get_auth_token(self.admin_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.get(self.vendor_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)  # We created 2 vendors in setup

        # Test filtering by status
        response = self.client.get(f"{self.vendor_list_url}?status=pending")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['status'], Vendor.PENDING)

        response = self.client.get(f"{self.vendor_list_url}?status=approved")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['status'], Vendor.APPROVED)

    def test_list_vendors_customer(self):
        """Test listing vendors as customer (should be forbidden)"""
        # Authenticate as customer
        token = self.get_auth_token(self.customer_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.get(self.vendor_list_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_vendor_detail_admin(self):
        """Test getting vendor details as admin"""
        # Authenticate as admin
        token = self.get_auth_token(self.admin_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.get(self.vendor_detail_url(self.vendor.id))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['business_name'], self.vendor.business_name)
        self.assertEqual(response.data['status'], self.vendor.status)

    def test_vendor_detail_customer(self):
        """Test getting vendor details as customer (should be forbidden)"""
        # Authenticate as customer
        token = self.get_auth_token(self.customer_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.get(self.vendor_detail_url(self.vendor.id))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_approve_vendor(self):
        """Test approving a vendor as admin"""
        # Authenticate as admin
        token = self.get_auth_token(self.admin_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.put(self.vendor_approve_url(self.vendor.id))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify vendor status was updated
        self.vendor.refresh_from_db()
        self.assertEqual(self.vendor.status, Vendor.APPROVED)

    def test_reject_vendor(self):
        """Test rejecting a vendor as admin"""
        # Authenticate as admin
        token = self.get_auth_token(self.admin_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        data = {
            'rejection_reason': 'Business details not sufficient'
        }
        response = self.client.put(self.vendor_reject_url(self.vendor.id), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify vendor status was updated
        self.vendor.refresh_from_db()
        self.assertEqual(self.vendor.status, Vendor.REJECTED)
        self.assertEqual(self.vendor.rejection_reason, data['rejection_reason'])

    def test_reject_vendor_without_reason(self):
        """Test rejecting a vendor without providing a reason (should fail)"""
        # Authenticate as admin
        token = self.get_auth_token(self.admin_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.put(self.vendor_reject_url(self.vendor.id), {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Verify vendor status was not updated
        self.vendor.refresh_from_db()
        self.assertEqual(self.vendor.status, Vendor.PENDING)

    def test_suspend_vendor(self):
        """Test suspending a vendor as admin"""
        # Authenticate as admin
        token = self.get_auth_token(self.admin_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        data = {
            'suspension_reason': 'Late payments'
        }
        response = self.client.put(self.vendor_suspend_url(self.approved_vendor.id), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify vendor status was updated
        self.approved_vendor.refresh_from_db()
        self.assertEqual(self.approved_vendor.status, Vendor.SUSPENDED)
        self.assertEqual(self.approved_vendor.suspension_reason, data['suspension_reason'])

    def test_ban_vendor(self):
        """Test banning a vendor as admin"""
        # Authenticate as admin
        token = self.get_auth_token(self.admin_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        data = {
            'ban_reason': 'Violation of terms of service'
        }
        response = self.client.put(self.vendor_ban_url(self.approved_vendor.id), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify vendor status was updated
        self.approved_vendor.refresh_from_db()
        self.assertEqual(self.approved_vendor.status, Vendor.BANNED)
        self.assertEqual(self.approved_vendor.ban_reason, data['ban_reason'])

    def test_delete_vendor(self):
        """Test deleting a vendor as admin"""
        # Authenticate as admin
        token = self.get_auth_token(self.admin_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.delete(self.vendor_delete_url(self.vendor.id))
        print(response.data)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Verify vendor was deleted
        self.assertFalse(Vendor.objects.filter(id=self.vendor.id).exists())
        # Verify user was also deleted (cascade delete)
        self.assertFalse(CustomUser.objects.filter(id=self.vendor_user.id).exists())

    def test_vendor_products_as_admin(self):
        """Test accessing vendor products as admin"""
        # Authenticate as admin
        token = self.get_auth_token(self.admin_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.get(self.vendor_products_url(self.vendor.id))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('products', response.data)

    def test_vendor_products_as_vendor_owner(self):
        """Test accessing own vendor products as vendor"""
        # Authenticate as vendor
        token = self.get_auth_token(self.vendor_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.get(self.vendor_products_url(self.vendor.id))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('products', response.data)

    def test_vendor_products_as_different_vendor(self):
        """Test accessing another vendor's products as vendor (should be forbidden)"""
        # Authenticate as approved vendor
        token = self.get_auth_token(self.approved_vendor_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.get(self.vendor_products_url(self.vendor.id))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_vendor_products_as_customer(self):
        """Test accessing vendor products as customer (should be forbidden)"""
        # Authenticate as customer
        token = self.get_auth_token(self.customer_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.get(self.vendor_products_url(self.vendor.id))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_unauthenticated_access(self):
        """Test unauthenticated access to vendor endpoints"""
        # No authentication
        self.client.credentials()

        # List vendors (admin only)
        response = self.client.get(self.vendor_list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # Vendor details (admin only)
        response = self.client.get(self.vendor_detail_url(self.vendor.id))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # Approve vendor (admin only)
        response = self.client.put(self.vendor_approve_url(self.vendor.id))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # Vendor products (vendor or admin)
        response = self.client.get(self.vendor_products_url(self.vendor.id))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
