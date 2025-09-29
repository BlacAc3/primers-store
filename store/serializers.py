from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.utils import extend_schema_field
from .models import CustomUser as User, Vendor
from .models import Product, ProductImage, Category, Tag, ProductReview, VendorReview, Cart, CartItem, Wishlist, WishlistItem, Order



class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    role = serializers.ChoiceField(
        choices=[
            ('customer', 'Customer'),
            ('vendor', 'Vendor'),
            ('admin', 'Admin'),
        ],
        required=True
    )
    username = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'role']

    def validate(self, attrs):
        # Ensure all required fields are provided
        required_fields = ['username', 'email', 'password', 'role']
        for field in required_fields:
            if field not in attrs or not attrs[field]:
                raise serializers.ValidationError({field: f"The {field} field is required."})
        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            role=validated_data['role']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        user = User.objects.filter(email=email).first()
        if user and user.check_password(password):
            tokens = RefreshToken.for_user(user)
            return {
                'access': str(tokens.access_token),
                'refresh': str(tokens),
            }
        raise serializers.ValidationError('Invalid credentials')

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs.get('refresh')
        return attrs

    def save(self, **kwargs):
        try:
            # Get the token object from the string
            token = RefreshToken(self.token)
            # Manually add the token to the blacklist
            token.blacklist()
        except Exception as e:
            raise serializers.ValidationError(f"Token error: {str(e)}")

class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'phone_number', 'address', 'role' ]

class UserSerializer(serializers.ModelSerializer):
    vendor = serializers.SerializerMethodField(read_only=True)

    # This nested serializer is used for representing Vendor data within the UserSerializer.
    # It is required for proper Swagger documentation to avoid warnings when auto-generating
    # the response schema for the 'vendor' field, which is populated by the 'get_vendor' method.
    class VendorDataSerializer(serializers.ModelSerializer):
        class Meta:
            model = Vendor
            fields = ['id', 'business_name', 'business_description', 'website', 'status']

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'phone_number','address', 'role', 'vendor']

    @extend_schema_field(VendorDataSerializer)
    def get_vendor(self, obj):
        """
        Retrieves and serializes vendor data if the user has a 'vendor' role.
        Returns None otherwise.
        """
        if obj.role == User.VENDOR:
            try:
                vendor = Vendor.objects.get(user=obj)
                return UserSerializer.VendorDataSerializer(vendor).data
            except Vendor.DoesNotExist:
                return None
        return None


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)



class VendorReviewSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = VendorReview
        fields = ['id', 'user', 'rating', 'comment', 'created_at']
        read_only_fields = ['id', 'user', 'created_at']
    rating = serializers.IntegerField(min_value=1, max_value=5)
    comment = serializers.CharField(max_length=500)
    created_at = serializers.DateTimeField(read_only=True)



# Vendor Serializers
class VendorRegistrationSerializer(serializers.ModelSerializer):
    user = RegisterSerializer()

    class Meta:
        model = Vendor
        fields = ['id', 'user', 'business_name', 'business_description', 'website']
        read_only_fields = ['id', 'status']

    def create(self, validated_data):
        user_data = validated_data.pop('user')
        user_data['role'] = 'vendor'  # Force role to be vendor

        # Create user first
        user_serializer = RegisterSerializer(data=user_data)
        user_serializer.is_valid(raise_exception=True)
        user = user_serializer.save()

        # Then create vendor profile
        vendor = Vendor.objects.create(user=user, **validated_data)
        return vendor


class VendorSerializer(serializers.ModelSerializer):
    user = UserDetailSerializer(read_only=True)

    class Meta:
        model = Vendor
        fields = [
            'id', 'user', 'business_name', 'business_description',
            'website', 'status', 'rejection_reason', 'suspension_reason',
            'ban_reason', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class VendorStatusUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = ['status', 'rejection_reason', 'suspension_reason', 'ban_reason']

    def validate(self, attrs):
        status = attrs.get('status')
        rejection_reason = attrs.get('rejection_reason')
        suspension_reason = attrs.get('suspension_reason')
        ban_reason = attrs.get('ban_reason')

        if status == Vendor.REJECTED and not rejection_reason:
            raise serializers.ValidationError({'rejection_reason': 'Rejection reason is required'})

        if status == Vendor.SUSPENDED and not suspension_reason:
            raise serializers.ValidationError({'suspension_reason': 'Suspension reason is required'})

        if status == Vendor.BANNED and not ban_reason:
            raise serializers.ValidationError({'ban_reason': 'Ban reason is required'})

        return attrs


class VendorApproveSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = ['status']
        read_only_fields = ['status']

    def update(self, instance, validated_data):
        instance.status = Vendor.APPROVED
        instance.save()
        return instance


class VendorRejectSerializer(serializers.ModelSerializer):
    rejection_reason = serializers.CharField(required=True)

    class Meta:
        model = Vendor
        fields = ['status', 'rejection_reason']
        read_only_fields = ['status']

    def update(self, instance, validated_data):
        instance.status = Vendor.REJECTED
        instance.rejection_reason = validated_data.get('rejection_reason')
        instance.save()
        return instance


class VendorSuspendSerializer(serializers.ModelSerializer):
    suspension_reason = serializers.CharField(required=True)

    class Meta:
        model = Vendor
        fields = ['status', 'suspension_reason']
        read_only_fields = ['status']

    def update(self, instance, validated_data):
        instance.status = Vendor.SUSPENDED
        instance.suspension_reason = validated_data.get('suspension_reason')
        instance.save()
        return instance


class VendorBanSerializer(serializers.ModelSerializer):
    ban_reason = serializers.CharField(required=True)

    class Meta:
        model = Vendor
        fields = ['status', 'ban_reason']
        read_only_fields = ['status']

    def update(self, instance, validated_data):
        instance.status = Vendor.BANNED
        instance.ban_reason = validated_data.get('ban_reason')
        instance.save()
        return instance


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name', 'description', 'image', 'category_parent']


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ['id', 'name']


class ProductReviewSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()

    class UserDataSerializer(serializers.Serializer):
        id = serializers.IntegerField(read_only=True)
        username = serializers.CharField(read_only=True)

    class Meta:
        model = ProductReview
        fields = ['id', 'user', 'rating', 'comment', 'created_at']
        read_only_fields = ['id', 'user', 'created_at']

    rating = serializers.IntegerField(min_value=1, max_value=5)
    comment = serializers.CharField(max_length=500)
    created_at = serializers.DateTimeField(read_only=True)

    @extend_schema_field(UserDataSerializer)
    def get_user(self, obj):
        return {'id': obj.user.id, 'username': obj.user.username}

class ProductImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductImage
        fields = ['id', 'image_url', 'alt_text', 'is_primary', 'display_order']


class ProductCreateSerializer(serializers.ModelSerializer):
    images = ProductImageSerializer(many=True, required=False)
    tags = serializers.SlugRelatedField(
        many=True,
        slug_field='name',
        queryset=Tag.objects.all(),
        required=False
    )

    class Meta:
        model = Product
        fields = [
            'id', 'name', 'description', 'price', 'sale_price',
            'stock_quantity', 'category', 'tags', 'listing_status', 'images'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'vendor']

    def create(self, validated_data):
        tags = []
        try:
            # Handle tags first - remove from validated data
            tag_names = validated_data.pop('tags', [])

            # Handle images - remove from validated data
            images_data = validated_data.pop('images', [])

            product = Product.objects.create(**validated_data)
            # Process tags - create any that don't exist
            for tag_name in tag_names:
                tag= Tag.objects.get(name=tag_name.name.lower())
                tags.append(tag)

            # Add tags to product
            product.tags.set(tags)

        # Create product images
            for image_data in images_data:
                ProductImage.objects.create(product=product, **image_data)
            return product
        except:
            if tags:
                for tag in tags:
                   tag.delete()
            return None


class ProductListSerializer(serializers.ModelSerializer):
    category = CategorySerializer(read_only=True)
    tags = TagSerializer(many=True, read_only=True)
    vendor_name = serializers.CharField(source='vendor.business_name', read_only=True)
    primary_image = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = [
            'id', 'name', 'description', 'price', 'sale_price',
            'stock_quantity', 'category', 'tags', 'listing_status',
            'vendor_name', 'primary_image', 'created_at'
        ]

    def get_primary_image(self, obj) -> str|None:
        primary = obj.images.filter(is_primary=True).first()
        if primary:
            return primary.image_url
        # If no primary image, return the first image or None
        image = obj.images.first()
        return image.image_url if image else None


class ProductDetailSerializer(serializers.ModelSerializer):
    category = CategorySerializer(read_only=True)
    tags = TagSerializer(many=True, read_only=True)
    images = ProductImageSerializer(many=True, read_only=True)
    vendor = serializers.SerializerMethodField()

    # Define a nested serializer to explicitly describe the structure of the vendor data
    # returned by get_vendor. This helps drf-spectacular generate accurate documentation.
    class VendorDetailDataSerializer(serializers.Serializer):
        id = serializers.IntegerField(read_only=True)
        business_name = serializers.CharField(read_only=True)
        status = serializers.CharField(read_only=True)

    class Meta:
        model = Product
        fields = [
            'id', 'name', 'description', 'price', 'sale_price',
            'stock_quantity', 'category', 'tags', 'listing_status',
            'vendor', 'images', 'created_at', 'updated_at'
        ]

    # Use extend_schema_field to provide a type hint for the return value of get_vendor,
    # resolving the drf-spectacular warning.
    @extend_schema_field(VendorDetailDataSerializer)
    def get_vendor(self, obj):
        return {
            'id': obj.vendor.id,
            'business_name': obj.vendor.business_name,
            'status': obj.vendor.status
        }


class ProductUpdateSerializer(serializers.ModelSerializer):
    images = ProductImageSerializer(many=True, required=False)
    tags = serializers.SlugRelatedField(
        many=True,
        slug_field='name',
        queryset=Tag.objects.all(),
        required=False
    )
    class Meta:
        model = Product
        fields = [
            'name', 'description', 'price', 'sale_price',
            'stock_quantity', 'category', 'tags', 'listing_status', 'images'
        ]

    def update(self, instance, validated_data):
        tags = []
        try:
            # Update tags to the instance
            if 'tags' in validated_data:
                tag_names = validated_data.pop('tags', [])
                for tag_name in tag_names:
                    tags.append(tag_name)
                instance.tags.set(tags)
            # Handle images if provided
            if 'images' in validated_data:
                images_data = validated_data.pop('images', [])
                # Clear existing images if new set is provided
                instance.images.all().delete()

                for image_data in images_data:
                    ProductImage.objects.create(product=instance, **image_data)

            # Update the remaining fields
            for attr, value in validated_data.items():
                setattr(instance, attr, value)

        except:
            if tags:
                for tag in tags:
                    tag.delete()

        instance.save()
        return instance


class CartItemSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source='product.name', read_only=True)
    product_price = serializers.DecimalField(source='product.price', max_digits=10, decimal_places=2, read_only=True)
    product_image = serializers.SerializerMethodField()

    class Meta:
        model = CartItem
        fields = ['id', 'product', 'product_name', 'product_price', 'product_image', 'quantity', 'added_at']
        read_only_fields = ['id', 'added_at']

    def get_product_image(self, obj) -> str | None:
        primary = obj.product.images.filter(is_primary=True).first()
        if primary:
            return primary.image_url
        image = obj.product.images.first()
        return image.image_url if image else None


class CartSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True, read_only=True)
    total_items = serializers.SerializerMethodField()
    total_price = serializers.SerializerMethodField()

    class Meta:
        model = Cart
        fields = ['id', 'user', 'items', 'total_items', 'total_price', 'created_at', 'updated_at']
        read_only_fields = ['id', 'user', 'created_at', 'updated_at']

    def get_total_items(self, obj):
        return round(obj.items.count(), 2) if obj.items else 0.00

    def get_total_price(self, obj):
        return round(sum(item.product.price * item.quantity for item in obj.items.all()), 2) if obj.items else 0.00


class AddCartItemSerializer(serializers.Serializer):
    product_id = serializers.IntegerField()
    quantity = serializers.IntegerField(min_value=1, default=1)


    def validate_product_id(self, value):
        try:
            Product.objects.get(id=value)
        except Product.DoesNotExist:
            raise serializers.ValidationError("Product does not exist.")
        return value


class UpdateCartItemSerializer(serializers.ModelSerializer):
    quantity = serializers.IntegerField(min_value=1)

    class Meta:
        model = CartItem
        fields = ['quantity']


class WishlistItemSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source='product.name', read_only=True)
    product_price = serializers.DecimalField(source='product.price', max_digits=10, decimal_places=2, read_only=True)
    product_image = serializers.SerializerMethodField()

    class Meta:
        model = WishlistItem
        fields = ['id', 'product', 'product_name', 'product_price', 'product_image', 'added_at']
        read_only_fields = ['id', 'added_at']

    def get_product_image(self, obj) -> str | None:
        primary = obj.product.images.filter(is_primary=True).first()
        if primary:
            return primary.image_url
        image = obj.product.images.first()
        return image.image_url if image else None


class WishlistSerializer(serializers.ModelSerializer):
    items = WishlistItemSerializer(many=True, read_only=True)
    total_items = serializers.SerializerMethodField()

    class Meta:
        model = Wishlist
        fields = ['id', 'user', 'items', 'total_items', 'created_at', 'updated_at']
        read_only_fields = ['id', 'user', 'created_at', 'updated_at']

    def get_total_items(self, obj):
        return obj.items.count()

# class AddWishlistItemSerializer(serializers.Serializer):
#     product_id = serializers.IntegerField()

#     def validate_product_id(self, value):
#         try:
#             product = Product.objects.get(id=value)
#             if not product.is_in_stock:
#                 raise serializers.ValidationError("This product is currently out of stock and cannot be added to the wishlist.")
#         except Product.DoesNotExist:
#             raise serializers.ValidationError("Product does not exist.")
#         return value


# class OrderDetailsSerializer(serializers.ModelSerializer):
#     items = serializers.ListField(child=serializers.IntegerField(), write_only=True, required=False,
#                                   help_text="List of product IDs to include in the order.")
#     class Meta:
#         model = OrderDetails
#         fields = ['id', 'user','created_at', 'total_amount', 'status', 'shipping_address', 'billing_address', 'payment_method', 'payment_status', 'transaction_id', 'items']
#         read_only_fields = ['id', 'user', 'created_at', 'total_amount']



#     def create(self, validated_data):
#         items_data = validated_data.pop('items', [])  # Extract item IDs from validated data

#         order_details = OrderDetails.objects.create(**validated_data)

#         # Add order items based on the provided product IDs
#         for product_id in items_data:
#             try:
#                 product = Product.objects.get(pk=product_id)
#                 Order.objects.create(order_details=order_details, product=product, quantity=1, price=product.price)  # You may adjust quantity here
#             except Product.DoesNotExist:
#                 order_details.delete()
#                 raise serializers.ValidationError(f"Product with id {product_id} not found.")

#         order_details.total_amount = sum(item.product.price * item.quantity for item in order_details.orderitem_set.all())
#         order_details.save()

#         return order_details

class OrderSerializer(serializers.ModelSerializer):
    product = serializers.PrimaryKeyRelatedField(queryset=Product.objects.all(), required=True)
    shipping_address = serializers.CharField(required=True)
    recipient_name = serializers.CharField(required=True)
    quantity = serializers.IntegerField(required=True, min_value=1)

    class Meta:
        model = Order
        fields = ['shipping_address','recipient_name', 'product', 'quantity']

    # def validate(self, attrs):
    #     if not attrs.get("shipping_address") or not attrs.get("recipient_name") or not attrs.get("quantity"):
    #         raise serializers.ValidationError("Missing Fields")
    #     return attrs

    def create(self, validated_data):
        # Access the request from the serializer context
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            user = request.user
            product = validated_data.get('product')

            if not product:
                raise serializers.ValidationError("Product not found.")
            # Create the order using the validated data and the authenticated user
            order = Order.objects.create(
                user=user,
                shipping_address=validated_data.get('shipping_address'),
                recipient_name=validated_data.get('recipient_name'),
                product=product,
                quantity=validated_data.get('quantity'),
                price=validated_data.get('product').price,
            )

            return order
        else:
            raise serializers.ValidationError("User not authenticated.")


class CartOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ['shipping_address','recipient_name']

    def validate(self, attrs):
        if not attrs.get("shipping_address"):
             raise serializers.ValidationError("Shipping address is required.")
        if not attrs.get("recipient_name"):
             raise serializers.ValidationError("Recepient name is required.")

        return attrs


class OrderStatusUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ['status']
