from rest_framework import permissions

class AllowAny(permissions.BasePermission):
    """
    Allows access to any user.
    """
    def has_permission(self, request, view):
        return True

class IsAuthenticated(permissions.BasePermission):
    """
    Allows access only to authenticated users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

class IsAdmin(permissions.BasePermission):
    """
    Allows access only to admin users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'admin'


class IsVendor(permissions.BasePermission):
    """
    Allows access only to vendor users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'vendor'

class IsCustomer(permissions.BasePermission):
    """
    Allows access only to Customer Users.
    """
    def has_permission(self,request, view):
        return request.user and request.user.is_authenticated and request.user.role=='customer'


class IsVendorOrAdmin(permissions.BasePermission):
    """
    Allows access to vendors for their own resources or admins for all resources.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and (
            request.user.role == 'admin' or request.user.role == 'vendor'
        )


class IsVendorOwnerOrAdmin(permissions.BasePermission):
    """
    Object-level permission to allow vendors to edit their own resources or admins to edit any.
    """
    def has_object_permission(self, request, view, obj):
        # Admin can do anything
        if request.user.role == 'admin':
            return True

        # Check if vendor owns this resource
        if hasattr(request.user, 'vendor_profile') and obj.id == request.user.vendor_profile.id:
            return True

        return False

class IsVendorProductOwner(permissions.BasePermission):
    """
    Object-level permission to allow vendors to edit their own products.
    """
    def has_object_permission(self, request, view, obj):
        # Check if user is authenticated and is a vendor
        if not request.user.is_authenticated or not hasattr(request.user, 'vendor_profile'):
            return False

        # Check if vendor owns this product
        return obj.vendor.id == request.user.vendor_profile.id


class IsOwnerOfOrder(permissions.BasePermission):
    """
    Object-level permission to allow customers to view/manage their own orders.
    """
    def has_object_permission(self, request, view, obj):
        # The order's user must match the authenticated user
        if hasattr(request.user, 'vendor_profile'):
            return False

        return obj.user.id == request.user.id
