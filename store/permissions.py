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
