from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    """
    Custom user model that can be either a vendor or customer
    based on the role field.
    """
    VENDOR = 'vendor'
    CUSTOMER = 'customer'
    ADMIN = 'admin'

    ROLE_CHOICES = [
        (VENDOR, 'Vendor'),
        (CUSTOMER, 'Customer'),
        (ADMIN, 'Admin')
    ]

    role = models.CharField(
        max_length=10,
        choices=ROLE_CHOICES,
        default=CUSTOMER,
    )
    phone_number = models.CharField(max_length=15, blank=True)
    address = models.TextField(blank=True)

    def is_vendor(self):
        return self.role == self.VENDOR

    def is_customer(self):
        return self.role == self.CUSTOMER

    def is_admin(self):
        return self.role == self.ADMIN
