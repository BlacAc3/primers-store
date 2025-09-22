from decimal import Decimal
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from store.models import CustomUser, Vendor, Product, Category, Cart, CartItem, Wishlist, WishlistItem, ProductImage


class CartWishlistTests(APITestCase):
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

        # Create admin user (should not access cart/wishlist directly)
        self.admin_data = {
            'username': 'admin',
            'email': 'admin@example.com',
            'password': 'adminpass123',
            'role': 'admin'
        }
        self.admin_user = CustomUser.objects.create_user(**self.admin_data)
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
        # Add an image to the product to ensure serializers handle it correctly
        ProductImage.objects.create(product=self.product, image_url="http://example.com/product.jpg", is_primary=True)

        self.out_of_stock_product = Product.objects.create(
            vendor=self.vendor_profile,
            name="Out of Stock Product",
            description="Product with no stock",
            price=Decimal('50.00'),
            stock_quantity=0,
            category=self.category,
            listing_status=Product.ACTIVE
        )
        ProductImage.objects.create(product=self.out_of_stock_product, image_url="http://example.com/oos_product.jpg", is_primary=True)


        # Endpoint URLs
        self.cart_url = reverse('cart-detail')
        self.cart_add_url = reverse('cart-add-item')
        self.wishlist_url = reverse('wishlist-detail')


    def _get_auth_token(self, user_data):
        """Helper method to get auth token for a user"""
        login_data = {
            'email': user_data['email'],
            'password': user_data['password']
        }
        response = self.client.post(reverse('auth-login'), login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response.data['access']

    # --- Cart Tests ---

    def test_get_cart_customer(self):
        """Test retrieving customer's cart"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        response = self.client.get(self.cart_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('items', response.data)
        self.assertIn('total_items', response.data)
        self.assertIn('total_price', response.data)
        self.assertEqual(response.data['total_items'], 0)
        self.assertEqual(response.data['total_price'], 0)
        self.assertEqual(response.data['user'], self.customer.id)

    def test_get_cart_unauthenticated(self):
        """Test retrieving cart without authentication"""
        response = self.client.get(self.cart_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_cart_non_customer_role(self):
        """Test retrieving cart with non-customer role (vendor/admin)"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.vendor_token}')
        response = self.client.get(self.cart_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        response = self.client.get(self.cart_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_add_item_to_cart(self):
        """Test adding a new item to cart"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        data = {
            'product_id': self.product.id,
            'quantity': 2
        }
        response = self.client.post(self.cart_add_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(CartItem.objects.count(), 1)
        cart_item = CartItem.objects.first()
        self.assertEqual(cart_item.product, self.product)
        self.assertEqual(cart_item.quantity, 2)

        # Verify cart details are updated
        cart_response = self.client.get(self.cart_url)
        self.assertEqual(cart_response.data['total_items'], 1)
        self.assertEqual(Decimal(cart_response.data['total_price']), Decimal('200.00')) # 2 * 100.00
        self.assertEqual(cart_response.data['items'][0]['product_image'], "http://example.com/product.jpg")


    def test_add_existing_item_to_cart_updates_quantity(self):
        """Test adding an existing item updates its quantity"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        cart, _ = Cart.objects.get_or_create(user=self.customer)
        CartItem.objects.create(cart=cart, product=self.product, quantity=1)

        data = {
            'product_id': self.product.id,
            'quantity': 3
        }
        response = self.client.post(self.cart_add_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(CartItem.objects.count(), 1) # Still one item
        cart_item = CartItem.objects.first()
        self.assertEqual(cart_item.quantity, 4) # 1 (initial) + 3 (added)

    def test_add_item_to_cart_out_of_stock(self):
        """Test adding an item that is out of stock"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        data = {
            'product_id': self.out_of_stock_product.id,
            'quantity': 1
        }
        response = self.client.post(self.cart_add_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('quantity', response.data)
        self.assertIn('available', str(response.data['quantity'])) # Check error message content


    def test_add_item_to_cart_exceeds_stock(self):
        """Test adding item with quantity exceeding available stock"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        data = {
            'product_id': self.product.id,
            'quantity': self.product.stock_quantity + 1 # Try to add more than available
        }
        response = self.client.post(self.cart_add_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('quantity', response.data)
        self.assertIn('available', str(response.data['quantity'])) # Check error message content


    def test_add_item_to_cart_exceeds_stock_existing_item(self):
        """Test adding more quantity to existing item in cart, exceeding stock"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        cart, _ = Cart.objects.get_or_create(user=self.customer)
        CartItem.objects.create(cart=cart, product=self.product, quantity=self.product.stock_quantity - 1) # Currently 9 in cart

        data = {
            'product_id': self.product.id,
            'quantity': 2 # Adding 2 would make total 11, exceeding stock (10)
        }
        response = self.client.post(self.cart_add_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('exceed', str(response.data['quantity']))


    def test_update_cart_item_quantity(self):
        """Test updating the quantity of a cart item"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        cart, _ = Cart.objects.get_or_create(user=self.customer)
        cart_item = CartItem.objects.create(cart=cart, product=self.product, quantity=1)

        update_url = reverse('cart-update-item', kwargs={'itemId': cart_item.id})
        data = {'quantity': 5}
        response = self.client.put(update_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        cart_item.refresh_from_db()
        self.assertEqual(cart_item.quantity, 5)

        # Verify cart totals are updated
        cart_response = self.client.get(self.cart_url)
        self.assertEqual(cart_response.data['total_items'], 1)
        self.assertEqual(Decimal(cart_response.data['total_price']), Decimal('500.00'))

    def test_update_cart_item_exceeds_stock(self):
        """Test updating cart item quantity beyond available stock"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        cart, _ = Cart.objects.get_or_create(user=self.customer)
        cart_item = CartItem.objects.create(cart=cart, product=self.product, quantity=1)

        update_url = reverse('cart-update-item', kwargs={'itemId': cart_item.id})
        data = {'quantity': self.product.stock_quantity + 1} # Exceed stock
        response = self.client.put(update_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('quantity', response.data)
        self.assertIn('available', str(response.data['quantity']))
        cart_item.refresh_from_db()
        self.assertEqual(cart_item.quantity, 1) # Quantity should not have changed


    def test_update_cart_item_nonexistent(self):
        """Test updating a non-existent cart item"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        non_existent_item_id = 999
        update_url = reverse('cart-update-item', kwargs={'itemId': non_existent_item_id})
        data = {'quantity': 2}
        response = self.client.put(update_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


    def test_remove_item_from_cart(self):
        """Test removing an item from cart"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        cart, _ = Cart.objects.get_or_create(user=self.customer)
        cart_item = CartItem.objects.create(cart=cart, product=self.product, quantity=1)

        remove_url = reverse('cart-remove-item', kwargs={'itemId': cart_item.id})
        response = self.client.delete(remove_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(CartItem.objects.count(), 0)

        # Verify cart totals are updated
        cart_response = self.client.get(self.cart_url)
        self.assertEqual(cart_response.data['total_items'], 0)
        self.assertEqual(cart_response.data['total_price'], 0)

    def test_remove_item_from_cart_nonexistent(self):
        """Test removing a non-existent item from cart"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        non_existent_item_id = 999
        remove_url = reverse('cart-remove-item', kwargs={'itemId': non_existent_item_id})
        response = self.client.delete(remove_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    # --- Wishlist Tests ---

    def test_get_wishlist_customer(self):
        """Test retrieving customer's wishlist"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        response = self.client.get(self.wishlist_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('items', response.data)
        self.assertIn('total_items', response.data)
        self.assertEqual(response.data['total_items'], 0)
        self.assertEqual(response.data['user'], self.customer.id)


    def test_get_wishlist_unauthenticated(self):
        """Test retrieving wishlist without authentication"""
        response = self.client.get(self.wishlist_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_wishlist_non_customer_role(self):
        """Test retrieving wishlist with non-customer role (vendor/admin)"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.vendor_token}')
        response = self.client.get(self.wishlist_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        response = self.client.get(self.wishlist_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_add_item_to_wishlist(self):
        """Test adding a product to wishlist"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        add_url = reverse('wishlist-add-item', kwargs={'productId': self.product.id})
        response = self.client.post(add_url, {}, format='json') # No body required, productId in URL
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(WishlistItem.objects.count(), 1)
        wishlist_item = WishlistItem.objects.first()
        self.assertEqual(wishlist_item.product, self.product)

        # Verify wishlist details are updated
        wishlist_response = self.client.get(self.wishlist_url)
        self.assertEqual(wishlist_response.data['total_items'], 1)
        self.assertEqual(wishlist_response.data['items'][0]['product'], self.product.id)
        self.assertEqual(wishlist_response.data['items'][0]['product_image'], "http://example.com/product.jpg")


    def test_add_duplicate_item_to_wishlist(self):
        """Test adding a product already in wishlist"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        wishlist, _ = Wishlist.objects.get_or_create(user=self.customer)
        WishlistItem.objects.create(wishlist=wishlist, product=self.product)

        add_url = reverse('wishlist-add-item', kwargs={'productId': self.product.id})
        response = self.client.post(add_url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('detail', response.data)
        self.assertEqual(response.data['detail'], 'Product already in wishlist.')
        self.assertEqual(WishlistItem.objects.count(), 1) # Still one item

    def test_add_out_of_stock_item_to_wishlist(self):
        """Test adding an out of stock product to wishlist"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        add_url = reverse('wishlist-add-item', kwargs={'productId': self.out_of_stock_product.id})
        response = self.client.post(add_url, {}, format='json')

        # As per AddWishlistItemSerializer validation, this should be 400.
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('out of stock', response.data['detail'])


    def test_remove_item_from_wishlist(self):
        """Test removing a product from wishlist"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        wishlist, _ = Wishlist.objects.get_or_create(user=self.customer)
        WishlistItem.objects.create(wishlist=wishlist, product=self.product)

        remove_url = reverse('wishlist-remove-item', kwargs={'productId': self.product.id})
        response = self.client.delete(remove_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(WishlistItem.objects.count(), 0)

        # Verify wishlist details are updated
        wishlist_response = self.client.get(self.wishlist_url)
        self.assertEqual(wishlist_response.data['total_items'], 0)

    def test_remove_nonexistent_item_from_wishlist(self):
        """Test removing a non-existent product from wishlist"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.customer_token}')
        # Ensure wishlist exists for the user to avoid 500 if the get_queryset expects one
        Wishlist.objects.get_or_create(user=self.customer)

        non_existent_product_id = 999
        remove_url = reverse('wishlist-remove-item', kwargs={'productId': non_existent_product_id})
        response = self.client.delete(remove_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
