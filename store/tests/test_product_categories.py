from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from store.models import Category, CustomUser
from django.contrib.auth import get_user_model


class CategoryTests(APITestCase):
    def setUp(self):
        self.category_data = {
            'name': 'Electronics',
            'description': 'Electronic gadgets and accessories',
        }
        self.category = Category.objects.create(**self.category_data)

        self.list_url = reverse('category-list-create')
        self.detail_url = reverse('category-detail', kwargs={'pk': self.category.pk})
        self.update_url = reverse('category-update', kwargs={'pk': self.category.pk})
        self.delete_url = reverse('category-delete', kwargs={'pk': self.category.pk})

        # Login URL
        self.login_url = reverse('auth-login')

        self.admin_user = CustomUser.objects.create_user(username='adminuser', password='testpassword', email='admin@example.com', role='admin')
        self.admin_token = self.get_auth_token({'email': self.admin_user.email, 'password': 'testpassword'})
        self.admin_client = self.client

        self.vendor_user = CustomUser.objects.create_user(username='vendoruser', password='testpassword', email='vendor@example.com', role='vendor')
        self.vendor_token = self.get_auth_token({'email': self.vendor_user.email, 'password': 'testpassword'})
        self.vendor_client = self.client

        self.customer_user = CustomUser.objects.create_user(username='customeruser', password='testpassword', email='customer@example.com', role='customer')
        self.customer_token = self.get_auth_token({'email': self.customer_user.email, 'password': 'testpassword'})
        self.customer_client = self.client


    def get_auth_token(self, user_data):
        """Helper method to get auth token for a user"""
        login_data = {
            'email': user_data['email'],
            'password': user_data['password']
        }
        response = self.client.post(self.login_url, login_data, format='json')
        return response.data['access']


    def test_create_category(self):
        data = {
            'name': 'Clothing',
            'description': 'Apparel and fashion items'
        }
        self.admin_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.admin_token)
        response = self.admin_client.post(self.list_url, data, format='json')
        # print(response.data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Category.objects.count(), 2)
        self.assertEqual(Category.objects.get(pk=2).name, 'Clothing')
        self.admin_client.credentials()

    def test_list_categories(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], 'Electronics')

    def test_retrieve_category(self):
        response = self.client.get(self.detail_url)
        # print(response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'Electronics')

    def test_update_category(self):
        data = {
            'name': 'Updated Electronics',
            'description': 'Updated description'
        }
        self.admin_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.admin_token)
        response = self.admin_client.put(self.update_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Category.objects.get(pk=self.category.pk).name, 'Updated Electronics')
        self.admin_client.credentials()

    def test_partial_update_category(self):
        data = {
            'name': 'Patched Electronics',
        }
        self.admin_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.admin_token)
        response = self.admin_client.patch(self.update_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Category.objects.get(pk=self.category.pk).name, 'Patched Electronics')
        self.admin_client.credentials()

    def test_delete_category(self):
        self.admin_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.admin_token)
        response = self.admin_client.delete(self.delete_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Category.objects.count(), 0)
        self.admin_client.credentials()

    def test_create_category_with_parent(self):
        parent_category = Category.objects.create(name="Parent Category", description="Parent")
        data = {
            'name': 'Child Category',
            'description': 'Child Category Description',
            'parent': parent_category.id
        }
        self.admin_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.admin_token)
        response = self.admin_client.post(self.list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        child_category = Category.objects.get(name='Child Category')
        self.assertEqual(child_category.parent, parent_category)
        self.admin_client.credentials()

    def test_update_category_image(self):
        data = {
            'name': 'Electronics',
            'description': 'Electronic gadgets and accessories',
            'image': 'http://example.com/image.jpg'
        }
        self.admin_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.admin_token)
        response = self.admin_client.put(self.update_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Category.objects.get(pk=self.category.pk).image, 'http://example.com/image.jpg')
        self.admin_client.credentials()

    def test_create_category_missing_name(self):
        data = {
            'description': 'Apparel and fashion items'
        }
        self.admin_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.admin_token)
        response = self.admin_client.post(self.list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.admin_client.credentials()

    def test_delete_nonexistent_category(self):
        nonexistent_url = reverse('category-delete', kwargs={'pk': 999})
        self.admin_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.admin_token)
        response = self.admin_client.delete(nonexistent_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.admin_client.credentials()

    def test_unauthorized_create_category(self):
        data = {
            'name': 'Unauthorized Category',
            'description': 'Should not be created'
        }
        self.customer_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.customer_token)
        response = self.customer_client.post(self.list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(Category.objects.count(), 1)
        self.customer_client.credentials()

    def test_unauthorized_update_category(self):
        data = {
            'name': 'Unauthorized Update',
            'description': 'Should not be updated'
        }
        self.customer_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.customer_token)
        response = self.customer_client.put(self.update_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(Category.objects.get(pk=self.category.pk).name, 'Electronics')
        self.customer_client.credentials()

    def test_unauthorized_delete_category(self):
        self.customer_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.customer_token)
        response = self.customer_client.delete(self.delete_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(Category.objects.count(), 1)
        self.customer_client.credentials()
