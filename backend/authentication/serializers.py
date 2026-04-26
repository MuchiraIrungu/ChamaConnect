from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from .models import User, OTP, OTPType

class UserSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(read_only= True)

    class Meta:
        model = User
        fields = ['id','email','first_name','last_name','full_name',
                  'phone','email_verified','is_active','created_at',]
        read_only_fields = fields

class AuthTokenSerializer(serializers.ModelSerializer):
    access = serializers.CharField(read_only = True)
    refresh = serializers.CharField(read_only = True)
    user = UserSerializer(read_only = True)

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length =8)
    password2 = serializers.CharField(write_only=True, label="Confirm password")

    class Meta:
        model = User
        fields = ["email", "first_name", "last_name", "phone", "password", "password2"]
        extra_kwargs = {
            "first_name": {"required": True},
            "last_name":  {"required": True},
        }
 
    def validate_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("An account with this email already exists.")
        return value.lower()
    
    def validate_password(self, value):
        validate_password(value)
        return value
    
    def validate(self, data):
        if data["password"] != data["password2"]:
            raise serializers.ValidationError({"password2": "Passwords do not match."})
        return data
 
    def create(self, validated_data):
        validated_data.pop("password2")
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)     # hashes before saving
        user.save()
        return user
    
class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only = True )

    def validate_email(self, value):
        return value.lower()
    
class LogoutSerializer(serializers.ModelSerializer):
    """
     FIX BUG-02: Client must send the refresh token so we can blacklist it.
     Without this, logout would only clear localStorage — server-side
     invalidation would be impossible.
    """
    refresh = serializers.CharField()

class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=8)
 
    def validate_new_password(self, value):
        validate_password(value)
        return value
 
    def validate(self, data):
        if data["old_password"] == data["new_password"]:
            raise serializers.ValidationError(
                {"new_password": "New password must differ from current password."}
            )
        return data
    
class RequestOTPSerializer(serializers.Serializer):
    """
    Used for: forgot password, account deletion initiation.
    Client sends only the email — server generates and emails the OTP.
    The OTP code is NEVER in the response.
    """
    email    = serializers.EmailField()
    otp_type = serializers.ChoiceField(choices=OTPType.choices)
 
    def validate_email(self, value):
        return value.lower()
    
class VerifyOTPSerializer(serializers.Serializer):
    """
    FIX BUG-07: This is the missing piece in ChamaConnect —
    the serializer that accepts the OTP the user received by email.
    Used for both password reset confirmation and account deletion confirmation.
    """
    email    = serializers.EmailField()
    code     = serializers.CharField(min_length=6, max_length=6)
    otp_type = serializers.ChoiceField(choices=OTPType.choices)
 
    def validate_email(self, value):
        return value.lower()
 
    def validate_code(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("OTP must be a 6-digit number.")
        return value
 
    def validate(self, data):
        """
        Cross-field validation: check that the OTP actually exists,
        belongs to this user, is the right type, and hasn't expired or been used.
        """
        try:
            user = User.objects.get(email=data["email"])
        except User.DoesNotExist:
            # Generic error — don't reveal that the email doesn't exist
            raise serializers.ValidationError("Invalid or expired verification code.")
 
        otp = (
            OTP.objects
            .filter(
                user=user,
                otp_type=data["otp_type"],
                code=data["code"],
                is_used=False,
            )
            .order_by("-created_at")
            .first()
        )
 
        if not otp or not otp.is_valid:
            raise serializers.ValidationError("Invalid or expired verification code.")
 
        data["otp_instance"] = otp
        data["user"]         = user
        return data
 
class ResetPasswordSerializer(serializers.Serializer):
    """
    Final step of password reset — client sends email + OTP + new password.
    """
    email        = serializers.EmailField()
    code         = serializers.CharField(min_length=6, max_length=6)
    new_password = serializers.CharField(write_only=True, min_length=8)
 
    def validate_new_password(self, value):
        validate_password(value)
        return value
 
    def validate(self, data):
        try:
            user = User.objects.get(email=data["email"].lower())
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired verification code.")
 
        otp = (
            OTP.objects
            .filter(
                user=user,
                otp_type=OTPType.PASSWORD_RESET,
                code=data["code"],
                is_used=False,
            )
            .order_by("-created_at")
            .first()
        )
 
        if not otp or not otp.is_valid:
            raise serializers.ValidationError("Invalid or expired verification code.")
 
        data["otp_instance"] = otp
        data["user"]         = user
        return data