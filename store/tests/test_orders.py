from decimal import Decimal
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from store.models import CustomUser, Vendor, Product, Category, Cart, CartItem, Wishlist, WishlistItem, ProductImage, Order

class OrderTests(APITestCase):
    def setUp(self):
        self.client = self.client # Use APITestCase's client

        # Create customer user
        self.customer_data = {
            'username': 'customer',
            'email': 'customer@example.com',
            'password': 'customerpass123',
            'role': 'customer'
        }
        self.customer = CustomUser.objects.create_user(**self.customer_data)
        self.customer_token = self._get_auth_token(self.customer_data)

        # Create vendor user (should not access cart/wishlist directly)
        self.vendor_data = {
            'username': 'vendor',
            'email': 'vendor@example.com',
            'password': 'vendorpass123',
            'role': 'vendor'
        }
        self.vendor_user = CustomUser.objects.create_user(**self.vendor_data)
        self.vendor_token = self._get_auth_token(self.vendor_data)
        # Create a vendor profile for the vendor user, as products require a vendor.
        self.vendor_profile = Vendor.objects.create(
            user=self.vendor_user,
            business_name="Test Vendor Business",
            business_description="This is a test vendor business",
            status=Vendor.APPROVED
        )

        # Create an admin user
        self.admin_data = {
            'username': 'admin',
            'email': 'admin@example.com',
            'password': 'adminpass123',
            'role': 'admin'
        }
        self.admin_user = CustomUser.objects.create_user(**self.admin_data)
        self.admin_user.is_staff = True  # Grant staff status for admin access
        self.admin_user.is_superuser = True #Grant superuser status
        self.admin_user.save()
        self.admin_token = self._get_auth_token(self.admin_data)


        # Create a category and products for testing
        self.category = Category.objects.create(name="Electronics")
        self.product = Product.objects.create(
            vendor=self.vendor_profile,
            name="Test Product",
            description="A great product",
            price=Decimal('100.00'),
            stock_quantity=10,
            category=self.category,
            listing_status=Product.ACTIVE
        )
        ProductImage.objects.create(product=self.product, image_url="http://example.com/product.jpg", is_primary=True)

        # Endpoint URLs
        self.order_list_create_url = reverse('order-list-create')

    def _get_auth_token(self, user_data):
        """Helper method to get auth token for a user"""
        login_data = {
            'email': user_data['email'],
            'password': user_data['password']
        }
        response = self.client.post(reverse('auth-login'), login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response.data['access']

    def test_create_order(self):
        """Test creating an order"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')

        # Data for creating the order
        data = {
            'shipping_address': '123 Test St',
            'recipient_name': 'Test Customer',
            'product': self.product.id,
            'quantity': 2,
            'price': self.product.price * 2 #redundant because its a read only field
        }

        response = self.client.post(self.order_list_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Check if order was created
        self.assertEqual(Order.objects.count(), 1)
        order = Order.objects.first()
        self.assertEqual(order.shipping_address, '123 Test St')
        self.assertEqual(order.recipient_name, 'Test Customer')
        self.assertEqual(order.product, self.product)
        self.assertEqual(order.quantity, 2)

    def test_create_order_missing_shipping_address(self):
        """Test creating order with missing shipping address"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')

        data = {
            'recipient_name': 'Test Customer',
            'product': self.product.id,
            'quantity': 1,
            'price': self.product.price
        }

        response = self.client.post(self.order_list_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Order.objects.count(), 0)

    def test_create_order_missing_recipient_name(self):
        """Test creating order with missing recipient name"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')

        data = {
            'shipping_address': '123 Test St',
            'product': self.product.id,
            'quantity': 1,
            'price': self.product.price
        }

        response = self.client.post(self.order_list_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Order.objects.count(), 0)

    def test_list_orders(self):
        """Test listing orders for a user"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')

        # Create an order for the user
        order = Order.objects.create(
            user=self.customer,
            shipping_address='123 Test St',
            recipient_name='Test Customer',
            product=self.product,
            quantity=1,
            price=self.product.price
        )

        response = self.client.get(self.order_list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['shipping_address'], '123 Test St')
        self.assertEqual(response.data[0]['recipient_name'], 'Test Customer')

    def test_get_order_detail(self):
        """Test getting order details for a user"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')

        # Create an order for the user
        order = Order.objects.create(
            user=self.customer,
            shipping_address='123 Test St',
            recipient_name='Test Customer',
            product=self.product,
            quantity=1,
            price=self.product.price
        )

        order_detail_url = reverse('order-detail', kwargs={'pk': order.id})
        response = self.client.get(order_detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['shipping_address'], '123 Test St')
        self.assertEqual(response.data['recipient_name'], 'Test Customer')

    def test_get_order_detail_unauthenticated(self):
        """Test getting order details without authentication"""

        # Create an order for the user
        order = Order.objects.create(
            user=self.customer,
            shipping_address='123 Test St',
            recipient_name='Test Customer',
            product=self.product,
            quantity=1,
            price=self.product.price
        )

        order_detail_url = reverse('order-detail', kwargs={'pk': order.id})
        self.client.credentials()  # Remove authentication
        response = self.client.get(order_detail_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_order_detail_other_user(self):
        """Test getting order details for a different user (should fail)"""
        # Create a different customer
        other_customer_data = {
            'username': 'other_customer',
            'email': 'other_customer@example.com',
            'password': 'otherpass123',
            'role': 'customer'
        }
        other_customer = CustomUser.objects.create_user(**other_customer_data)
        other_customer_token = self._get_auth_token(other_customer_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {other_customer_token}')

        # Create an order for the original customer
        order = Order.objects.create(
            user=self.customer,
            shipping_address='123 Test St',
            recipient_name='Test Customer',
            product=self.product,
            quantity=1,
            price=self.product.price
        )

        order_detail_url = reverse('order-detail', kwargs={'pk': order.id})
        response = self.client.get(order_detail_url)

        # Expect a 403 Forbidden because the other customer doesn't own the order.
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_get_order_detail_admin(self):
        """Test getting order details as an admin"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')

        # Create an order for the customer
        order = Order.objects.create(
            user=self.customer,
            shipping_address='123 Test St',
            recipient_name='Test Customer',
            product=self.product,
            quantity=1,
            price=self.product.price
        )

        order_detail_url = reverse('order-detail', kwargs={'pk': order.id})
        response = self.client.get(order_detail_url)

        # Expect a 200 OK because the admin should be able to access any order.
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['shipping_address'], '123 Test St')
        self.assertEqual(response.data['recipient_name'], 'Test Customer')

    def test_update_order_status(self):
        """Test updating the order status as an admin"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')

        # Create an order for the customer
        order = Order.objects.create(
            user=self.customer,
            shipping_address='123 Test St',
            recipient_name='Test Customer',
            product=self.product,
            quantity=1,
            price=self.product.price,
            status=Order.PENDING  # Set initial status
        )

        order_status_update_url = reverse('order-status-update', kwargs={'pk': order.id})
        data = {'status': Order.SHIPPED}  # Update status to 'shipped'
        response = self.client.put(order_status_update_url, data, format='json')

        # Expect a 200 OK if the update was successful
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Refresh the order from the database to check if the status was updated
        order.refresh_from_db()
        self.assertEqual(order.status, Order.SHIPPED)  # Check if status was actually updated
