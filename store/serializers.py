from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser as User, Vendor



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
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role']

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)


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
    user = UserSerializer(read_only=True)

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
