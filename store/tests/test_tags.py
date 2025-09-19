from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from store.models import Tag, CustomUser


class TagTests(APITestCase):
    def setUp(self):
        self.tag_data = {
            'name': 'Electronics'
        }
        self.tag = Tag.objects.create(**self.tag_data)

        self.list_url = reverse('tag-list-create')
        self.detail_url = reverse('tag-detail', kwargs={'pk': self.tag.pk})
        self.update_url = reverse('tag-update', kwargs={'pk': self.tag.pk})
        self.delete_url = reverse('tag-delete', kwargs={'pk': self.tag.pk})

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

    def test_create_tag(self):
        data = {
            'name': 'Clothing'
        }
        self.admin_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.admin_token)
        response = self.admin_client.post(self.list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Tag.objects.count(), 2)
        self.assertEqual(Tag.objects.get(pk=2).name, 'Clothing')
        self.admin_client.credentials()

    def test_list_tags(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], 'Electronics')

    def test_retrieve_tag(self):
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'Electronics')

    def test_update_tag(self):
        data = {
            'name': 'Updated Electronics'
        }
        self.admin_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.admin_token)
        response = self.admin_client.put(self.update_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Tag.objects.get(pk=self.tag.pk).name, 'Updated Electronics')
        self.admin_client.credentials()

    def test_partial_update_tag(self):
        data = {
            'name': 'Patched Electronics'
        }
        self.admin_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.admin_token)
        response = self.admin_client.patch(self.update_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Tag.objects.get(pk=self.tag.pk).name, 'Patched Electronics')
        self.admin_client.credentials()

    def test_delete_tag(self):
        self.admin_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.admin_token)
        response = self.admin_client.delete(self.delete_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Tag.objects.count(), 0)
        self.admin_client.credentials()

    def test_create_tag_missing_name(self):
        data = {}
        self.admin_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.admin_token)
        response = self.admin_client.post(self.list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.admin_client.credentials()

    def test_delete_nonexistent_tag(self):
        nonexistent_url = reverse('tag-delete', kwargs={'pk': 999})
        self.admin_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.admin_token)
        response = self.admin_client.delete(nonexistent_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.admin_client.credentials()

    def test_unauthorized_create_tag(self):
        data = {
            'name': 'Unauthorized Tag'
        }
        self.customer_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.customer_token)
        response = self.customer_client.post(self.list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(Tag.objects.count(), 1)
        self.customer_client.credentials()

    def test_unauthorized_update_tag(self):
        data = {
            'name': 'Unauthorized Update'
        }
        self.customer_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.customer_token)
        response = self.customer_client.put(self.update_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(Tag.objects.get(pk=self.tag.pk).name, 'Electronics')
        self.customer_client.credentials()

    def test_unauthorized_delete_tag(self):
        self.customer_client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.customer_token)
        response = self.customer_client.delete(self.delete_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(Tag.objects.count(), 1)
        self.customer_client.credentials()
