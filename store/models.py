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


class Vendor(models.Model):
    """
    Vendor profile model with additional vendor-specific information
    """
    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'
    SUSPENDED = 'suspended'
    BANNED = 'banned'

    STATUS_CHOICES = [
        (PENDING, 'Pending'),
        (APPROVED, 'Approved'),
        (REJECTED, 'Rejected'),
        (SUSPENDED, 'Suspended'),
        (BANNED, 'Banned'),
    ]

    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='vendor_profile')
    business_name = models.CharField(max_length=100)
    business_description = models.TextField()
    website = models.URLField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=PENDING)
    rejection_reason = models.TextField(blank=True, null=True)
    suspension_reason = models.TextField(blank=True, null=True)
    ban_reason = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.business_name} ({self.status})"
