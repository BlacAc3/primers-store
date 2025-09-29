from decimal import Decimal
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from store.models import CustomUser, Vendor, Product, Category, Cart, CartItem, Wishlist, WishlistItem, ProductImage, Order

class CartOrderCreateTests(APITestCase):
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
        self.cart_order_create_url = reverse('cart-order-create')

    def _get_auth_token(self, user_data):
        """Helper method to get auth token for a user"""
        login_data = {
            'email': user_data['email'],
            'password': user_data['password']
        }
        response = self.client.post(reverse('auth-login'), login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response.data['access']

    def test_create_order_from_cart(self):
        """Test creating an order from items in the cart"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')

        # Add item to cart first
        cart = Cart.objects.create(user=self.customer)
        CartItem.objects.create(cart=cart, product=self.product, quantity=2)
        initial_stock = self.product.stock_quantity

        # Data for creating the order
        data = {
            'shipping_address': '123 Test St',
            'recipient_name': 'Test Customer',
        }

        response = self.client.post(self.cart_order_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Check if order was created
        self.assertEqual(Order.objects.count(), 1)
        order = Order.objects.first()
        self.assertEqual(order.shipping_address, '123 Test St')
        self.assertEqual(order.recipient_name, 'Test Customer')
        self.assertEqual(order.product, self.product)
        self.assertEqual(order.quantity, 2)

        # Verify cart is cleared
        self.assertEqual(CartItem.objects.count(), 0)

        # Verify product stock is reduced
        self.product.refresh_from_db()
        self.assertEqual(self.product.stock_quantity, initial_stock - 2)

    def test_create_order_from_empty_cart(self):
        """Test creating an order from an empty cart"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')

        # Data for creating the order
        data = {
            'shipping_address': '123 Test St',
            'recipient_name': 'Test Customer',
            'product_ids': []  # Empty cart
        }

        response = self.client.post(self.cart_order_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(Order.objects.count(), 0)

    def test_create_order_missing_shipping_address(self):
        """Test creating order with missing shipping address"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')

        # Add item to cart first
        cart = Cart.objects.create(user=self.customer)
        CartItem.objects.create(cart=cart, product=self.product, quantity=1)

        data = {
            'recipient_name': 'Test Customer',
            'product_ids': [self.product.id]
        }

        response = self.client.post(self.cart_order_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Order.objects.count(), 0)

    def test_create_order_missing_recipient_name(self):
        """Test creating order with missing recipient name"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')

        # Add item to cart first
        cart = Cart.objects.create(user=self.customer)
        CartItem.objects.create(cart=cart, product=self.product, quantity=1)

        data = {
            'shipping_address': '123 Test St',
            'product_ids': [self.product.id]
        }

        response = self.client.post(self.cart_order_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Order.objects.count(), 0)
