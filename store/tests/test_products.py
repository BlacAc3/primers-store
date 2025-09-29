from decimal import Decimal
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from store.models import CustomUser, Vendor, Product, Category, Tag, ProductImage, ProductReview


class ProductManagementTests(TestCase):
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

        # Create approved vendor
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

        self.vendor = Vendor.objects.create(
            user=self.vendor_user,
            business_name="Test Vendor Business",
            business_description="This is a test vendor business",
            website="https://testvendor.com",
            status=Vendor.APPROVED
        )

        # Create another approved vendor
        self.vendor2_data = {
            'username': 'vendor2',
            'email': 'vendor2@example.com',
            'password': 'vendor2pass123',
            'role': 'vendor'
        }
        self.vendor2_user = CustomUser.objects.create_user(
            username=self.vendor2_data['username'],
            email=self.vendor2_data['email'],
            password=self.vendor2_data['password'],
            role=self.vendor2_data['role']
        )

        self.vendor2 = Vendor.objects.create(
            user=self.vendor2_user,
            business_name="Another Vendor Business",
            business_description="This is another test vendor business",
            website="https://anothervendor.com",
            status=Vendor.APPROVED
        )

        # Create categories
        self.category = Category.objects.create(
            name="Test Category",
            description="This is a test category"
        )

        self.sub_category = Category.objects.create(
            name="Test Subcategory",
            description="This is a test subcategory",
            category_parent=self.category
        )

        # Create tags
        self.tag1 = Tag.objects.create(name="tag1")
        self.tag2 = Tag.objects.create(name="tag2")

        # Create a product
        self.product = Product.objects.create(
            vendor=self.vendor,
            name="Test Product",
            description="This is a test product",
            price=Decimal('19.99'),
            stock_quantity=100,
            category=self.category,
            listing_status=Product.ACTIVE
        )

        # Add tags to product
        self.product.tags.add(self.tag1, self.tag2)

        # Add image to product
        self.product_image = ProductImage.objects.create(
            product=self.product,
            image_url="https://example.com/image.jpg",
            alt_text="Test Image",
            is_primary=True
        )

        # Create another product (draft) for the same vendor
        self.draft_product = Product.objects.create(
            vendor=self.vendor,
            name="Draft Product",
            description="This is a draft product",
            price=Decimal('29.99'),
            stock_quantity=50,
            category=self.sub_category,
            listing_status=Product.DRAFT
        )

        # Create a product for another vendor
        self.other_vendor_product = Product.objects.create(
            vendor=self.vendor2,
            name="Other Vendor Product",
            description="This is a product from another vendor",
            price=Decimal('15.99'),
            stock_quantity=75,
            category=self.category,
            listing_status=Product.ACTIVE
        )

        # Endpoint URLs
        self.product_list_url = reverse('product-list')
        self.product_create_url = reverse('product-create')
        self.product_detail_url = f'/api/products/{self.product.id}/'
        self.draft_product_detail_url = f'/api/products/{self.draft_product.id}/'
        self.product_update_url = f'/api/products/{self.product.id}/update/'
        self.product_delete_url = f'/api/products/{self.product.id}/delete/'
        self.product_review_url = f'/api/products/{self.product.id}/reviews/'

        # Login URL
        self.login_url = reverse('auth-login')

    def get_auth_token(self, user_data):
        """Helper method to get auth token for a user"""
        login_data = {
            'email': user_data['email'],
            'password': user_data['password']
        }
        response = self.client.post(self.login_url, login_data, format='json')
        return response.data['access']

    def test_create_product_as_vendor(self):
        """Test creating a product as a vendor"""
        # Authenticate as vendor
        token = self.get_auth_token(self.vendor_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        # Create product data
        data = {
            'name': 'New Test Product',
            'description': 'This is a new test product description',
            'price': '24.99',
            'stock_quantity': 50,
            'category': self.category.id,
            'tags': ['new', 'test'],
            'listing_status': Product.ACTIVE,
            'images': [
                {
                    'image_url': 'https://example.com/new-image.jpg',
                    'alt_text': 'New test image',
                    'is_primary': True
                }
            ]
        }

        response = self.client.post(self.product_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Product.objects.count(), 4)  # Was 3 + new one

        # Verify product was created correctly
        new_product = Product.objects.latest('created_at')
        self.assertEqual(new_product.name, data['name'])
        self.assertEqual(new_product.vendor.id, self.vendor.id)
        self.assertEqual(new_product.price, Decimal(data['price']))

        # Verify tags were created and associated
        self.assertEqual(new_product.tags.count(), 2)
        self.assertTrue(new_product.tags.filter(name='new').exists())
        self.assertTrue(new_product.tags.filter(name='test').exists())

        # Verify image was created
        self.assertEqual(new_product.images.count(), 1)
        self.assertEqual(new_product.images.first().image_url, data['images'][0]['image_url'])

    def test_create_product_as_customer(self):
        """Test creating a product as a customer (should fail)"""
        # Authenticate as customer
        token = self.get_auth_token(self.customer_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        data = {
            'name': 'New Product',
            'description': 'This is a new product',
            'price': '14.99',
            'stock_quantity': 25,
            'category': self.category.id,
            'listing_status': Product.ACTIVE
        }

        response = self.client.post(self.product_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(Product.objects.count(), 3)  # No new product was created

    def test_list_products_public(self):
        """Test listing products publicly"""
        # No authentication needed
        response = self.client.get(self.product_list_url)

        # Should only show active products, not drafts
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)  # 2 active products (1 from each vendor)

        # Verify the correct fields are included
        self.assertIn('name', response.data[0])
        self.assertIn('price', response.data[0])
        self.assertIn('vendor_name', response.data[0])
        self.assertIn('primary_image', response.data[0])

    def test_filter_products_by_category(self):
        """Test filtering products by category"""
        response = self.client.get(f"{self.product_list_url}?category={self.category.id}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)  # 2 products in the main category

        response = self.client.get(f"{self.product_list_url}?category={self.sub_category.id}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)  # 0 active products in subcategory (draft one is not counted)

    def test_filter_products_by_vendor(self):
        """Test filtering products by vendor"""
        response = self.client.get(f"{self.product_list_url}?vendor={self.vendor.id}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)  # 1 active product from this vendor
        self.assertEqual(response.data[0]['name'], self.product.name)

        response = self.client.get(f"{self.product_list_url}?vendor={self.vendor2.id}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)  # 1 active product from this vendor
        self.assertEqual(response.data[0]['name'], self.other_vendor_product.name)

    def test_filter_products_by_price(self):
        """Test filtering products by price range"""
        response = self.client.get(f"{self.product_list_url}?priceMin=15&priceMax=20")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)  # Both products are in this range

        response = self.client.get(f"{self.product_list_url}?priceMin=16")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)  # Only the 19.99 product

        response = self.client.get(f"{self.product_list_url}?priceMax=15")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)  # No products under 15

    def test_search_products(self):
        """Test searching products"""
        response = self.client.get(f"{self.product_list_url}?q=test")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)  # Both active products have "test" in their name/description

        response = self.client.get(f"{self.product_list_url}?q=other")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)  # Only one product has "other" in its name/description

    def test_product_detail_public(self):
        """Test getting product detail publicly"""
        response = self.client.get(self.product_detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], self.product.name)
        self.assertEqual(response.data['price'], str(self.product.price))
        self.assertEqual(response.data['vendor']['business_name'], self.vendor.business_name)
        self.assertEqual(len(response.data['images']), 1)
        self.assertEqual(len(response.data['tags']), 2)

    def test_draft_product_detail_public(self):
        """Test that public users can't view draft products"""
        response = self.client.get(self.draft_product_detail_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_draft_product_detail_owner(self):
        """Test that vendor owner can view their draft products"""
        # Authenticate as the vendor owner
        token = self.get_auth_token(self.vendor_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.get(self.draft_product_detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], self.draft_product.name)
        self.assertEqual(response.data['listing_status'], Product.DRAFT)

    def test_draft_product_detail_admin(self):
        """Test that admin can view draft products from any vendor"""
        # Authenticate as admin
        token = self.get_auth_token(self.admin_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.get(self.draft_product_detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], self.draft_product.name)

    def test_draft_product_detail_other_vendor(self):
        """Test that other vendors can't view draft products"""
        # Authenticate as the second vendor
        token = self.get_auth_token(self.vendor2_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.get(self.draft_product_detail_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_update_product_owner(self):
        """Test updating a product as the owner vendor"""
        # Authenticate as the vendor owner
        token = self.get_auth_token(self.vendor_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        data = {
            'name': 'Updated Product Name',
            'description': 'Updated product description',
            'price': '25.99',
            'sale_price': '22.99',
            'stock_quantity': 75
        }

        response = self.client.patch(self.product_update_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify changes were saved
        self.product.refresh_from_db()
        self.assertEqual(self.product.name, data['name'])
        self.assertEqual(self.product.description, data['description'])
        self.assertEqual(self.product.price, Decimal(data['price']))
        self.assertEqual(self.product.sale_price, Decimal(data['sale_price']))
        self.assertEqual(self.product.stock_quantity, data['stock_quantity'])

    def test_update_product_other_vendor(self):
        """Test that other vendors can't update products they don't own"""
        # Authenticate as the second vendor
        token = self.get_auth_token(self.vendor2_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        data = {
            'name': 'Unauthorized Update',
            'price': '9.99'
        }

        response = self.client.patch(self.product_update_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Verify product was not changed
        self.product.refresh_from_db()
        self.assertEqual(self.product.name, 'Test Product')  # Original name

    def test_update_product_admin(self):
        """Test that admin can update any product"""
        # Authenticate as admin
        token = self.get_auth_token(self.admin_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        data = {
            'name': 'Admin Updated Name',
            'price': '18.99'
        }

        response = self.client.patch(self.product_update_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify changes were saved
        self.product.refresh_from_db()
        self.assertEqual(self.product.name, data['name'])
        self.assertEqual(self.product.price, Decimal(data['price']))

    def test_update_product_tags(self):
        """Test updating product tags"""
        # Authenticate as the vendor owner
        token = self.get_auth_token(self.vendor_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        data = {
            'tags': ['newtag1', 'newtag2', 'newtag3']
        }

        response = self.client.patch(self.product_update_url, data, format='json')
        # print(response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify tags were updated
        self.product.refresh_from_db()
        self.assertEqual(self.product.tags.count(), 3)
        self.assertTrue(self.product.tags.filter(name='newtag1').exists())
        self.assertTrue(self.product.tags.filter(name='newtag2').exists())
        self.assertTrue(self.product.tags.filter(name='newtag3').exists())
        self.assertFalse(self.product.tags.filter(name='tag1').exists())  # Old tag removed

    def test_update_product_images(self):
        """Test updating product images"""
        # Authenticate as the vendor owner
        token = self.get_auth_token(self.vendor_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        data = {
            'images': [
                {
                    'image_url': 'https://example.com/new-image1.jpg',
                    'alt_text': 'New image 1',
                    'is_primary': True
                },
                {
                    'image_url': 'https://example.com/new-image2.jpg',
                    'alt_text': 'New image 2',
                    'is_primary': False
                }
            ]
        }

        response = self.client.patch(self.product_update_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify images were updated
        self.product.refresh_from_db()
        self.assertEqual(self.product.images.count(), 2)
        self.assertEqual(self.product.images.filter(is_primary=True).count(), 1)
        self.assertEqual(self.product.images.filter(is_primary=True).first().image_url, 'https://example.com/new-image1.jpg')

    def test_delete_product_owner(self):
        """Test deleting (disabling) a product as the owner vendor"""
        # Authenticate as the vendor owner
        token = self.get_auth_token(self.vendor_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.delete(self.product_delete_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Verify product was soft-deleted (status changed to DISABLED)
        self.product.refresh_from_db()
        self.assertEqual(self.product.listing_status, Product.DISABLED)

        # Verify it no longer appears in product listings
        response = self.client.get(self.product_list_url)
        product_ids = [product['id'] for product in response.data]
        self.assertNotIn(self.product.id, product_ids)

    def test_delete_product_other_vendor(self):
        """Test that other vendors can't delete products they don't own"""
        # Authenticate as the second vendor
        token = self.get_auth_token(self.vendor2_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.delete(self.product_delete_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Verify product was not deleted
        self.product.refresh_from_db()
        self.assertEqual(self.product.listing_status, Product.ACTIVE)

    def test_delete_product_admin(self):
        """Test that admin can delete any product"""
        # Authenticate as admin
        token = self.get_auth_token(self.admin_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.delete(self.product_delete_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Verify product was soft-deleted
        self.product.refresh_from_db()
        self.assertEqual(self.product.listing_status, Product.DISABLED)

    def test_create_product_validation(self):
        """Test product creation validation"""
        # Authenticate as vendor
        token = self.get_auth_token(self.vendor_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        # Test missing required fields
        data = {
            'name': 'Incomplete Product',
            # Missing description
            'price': '19.99',
            # Missing stock_quantity
            # Missing category
        }

        response = self.client.post(self.product_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Test invalid price
        data = {
            'name': 'Invalid Price Product',
            'description': 'This has an invalid price',
            'price': 'not-a-price',
            'stock_quantity': 50,
            'category': self.category.id
        }

        response = self.client.post(self.product_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Test non-existent category
        data = {
            'name': 'Invalid Category Product',
            'description': 'This has an invalid category',
            'price': '19.99',
            'stock_quantity': 50,
            'category': 999  # Non-existent ID
        }

        response = self.client.post(self.product_create_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_product_review(self):
        """Test creating a product review"""
        # Authenticate as customer
        token = self.get_auth_token(self.customer_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        # Create review data
        data = {
            'rating': 5,
            'comment': 'This is a great product!'
        }

        response = self.client.post(self.product_review_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify review was created
        self.assertEqual(ProductReview.objects.count(), 1)
        review = ProductReview.objects.first()
        self.assertEqual(review.product, self.product)
        self.assertEqual(review.user, self.customer)
        self.assertEqual(review.rating, data['rating'])
        self.assertEqual(review.comment, data['comment'])

    def test_create_product_review_unauthenticated(self):
        """Test creating a product review without authentication (should fail)"""
        # Create review data
        data = {
            'rating': 4,
            'comment': 'This is a good product.'
        }

        response = self.client.post(self.product_review_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(ProductReview.objects.count(), 0)

    def test_get_product_reviews(self):
        """Test getting a list of product reviews"""
        # Create a review first
        ProductReview.objects.create(
            product=self.product,
            user=self.customer,
            rating=4,
            comment='I like this product'
        )

        response = self.client.get(self.product_review_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

        # Verify review data
        review_data = response.data[0]
        self.assertEqual(review_data['rating'], 4)
        self.assertEqual(review_data['comment'], 'I like this product')
        self.assertEqual(review_data['user']['username'], self.customer.username)

    def test_delete_product_review_admin(self):
        """Test deleting a product review as admin"""
        # Create a review first
        review = ProductReview.objects.create(
            product=self.product,
            user=self.customer,
            rating=4,
            comment='I like this product'
        )
        review_delete_url = reverse('product-review-delete', kwargs={'pk': review.pk})

        # Authenticate as admin
        token = self.get_auth_token(self.admin_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.delete(review_delete_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Verify review was deleted
        self.assertEqual(ProductReview.objects.count(), 0)

    def test_delete_product_review_unauthorized(self):
        """Test deleting a product review as an unauthorized user"""
        # Create a review first
        review = ProductReview.objects.create(
            product=self.product,
            user=self.customer,
            rating=4,
            comment='I like this product'
        )
        review_delete_url = reverse('product-review-delete', kwargs={'pk': review.pk})

        # Authenticate as customer (not admin)
        token = self.get_auth_token(self.customer_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        response = self.client.delete(review_delete_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Verify review was not deleted
        self.assertEqual(ProductReview.objects.count(), 1)
