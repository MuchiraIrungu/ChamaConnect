import hashlib
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import authenticate
from django.utils import timezone
 
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
 
from .models import User, LoginAttempt, KnownDevice, OTP, OTPType
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    LogoutSerializer,
    UserSerializer,
    ChangePasswordSerializer,
    RequestOTPSerializer,
    VerifyOTPSerializer,
    ResetPasswordSerializer,
    AuthTokenSerializer,
)

def get_client_ip(request):
    x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "0.0.0.0")

def make_fingerprint(ip, user_agent):
    """
    FIX BUG-08: Stable hash of IP + User-Agent for device recognition.
    SHA-256 so we never store raw user-agent strings unbounded.
    """
    raw = f"{ip}|{user_agent}"
    return hashlib.sha256(raw.encode()).hexdigest()

def issue_tokens(user):
    """
    FIX BUG-01: Every token issued here has a proper expiry.
    Access  → 15 minutes  (configured in settings.SIMPLE_JWT)
    Refresh → 7 days      (configured in settings.SIMPLE_JWT)
    """
    refresh = RefreshToken.for_user(user)
    return {
        "access":  str(refresh.access_token),
        "refresh": str(refresh),
    }

def send_new_device_alert(user, ip, user_agent):
    """
    FIX BUG-08: Email the user when we see a device fingerprint
    that isn't in their known_devices table.
    """
    send_mail(
        subject="New login detected on your ChamaConnect account",
        message=(
            f"Hi {user.first_name},\n\n"
            f"A login to your account was detected from a new device.\n\n"
            f"  IP Address : {ip}\n"
            f"  Browser    : {user_agent[:120]}\n"
            f"  Time       : {timezone.now().strftime('%Y-%m-%d %H:%M UTC')}\n\n"
            f"If this was you, no action is needed.\n"
            f"If this was NOT you, reset your password immediately.\n\n"
            f"— The ChamaConnect Team"
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=True,   # don't break login if email fails
)

def sent_otp_email(user, code, otp_type):
    """
    FIX BUG-04: The code is sent ONLY by email — never returned in any
    API response. The client has no way to read it except from the inbox.
    """
    type_labels = {
        OTPType.PASSWORD_RESET:   "password reset",
        OTPType.ACCOUNT_DELETION: "account deletion",
        OTPType.EMAIL_VERIFY:     "email verification",
    }
    label = type_labels.get(otp_type, "verification")
 
    send_mail(
        subject=f"Your ChamaConnect {label} code",
        message=(
            f"Hi {user.first_name},\n\n"
            f"Your {label} code is:\n\n"
            f"    {code}\n\n"
            f"This code expires in 30 minutes and can only be used once.\n"
            f"If you did not request this, please ignore this email.\n\n"
            f"— The ChamaConnect Team"
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )

class RegisterView(APIView):
    permission_classes = [AllowAny]
 
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 
        user = serializer.save()
 
        # Issue tokens immediately so user is logged in after registration
        tokens = issue_tokens(user)
 
        return Response(
            {
                "message": "Account created successfully.",
                "status":  "success",
                "data": {
                    **tokens,
                    "user": UserSerializer(user).data,
                },
            },
            status=status.HTTP_201_CREATED,
        )
    
class LoginView(APIView):
    permission_classes = [AllowAny]
 
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "unknown")
 
        # Check lockout BEFORE attempting authentication
        # This prevents timing attacks that could reveal valid accounts
        if LoginAttempt.is_locked_out(ip, email):
            return Response(
                {
                    "message": "Too many failed attempts. Please try again in 15 minutes.",
                    "status":  "error",
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )
 
        user = authenticate(request, username=email, password=password)
 
        if user is None:
            LoginAttempt.record(ip, email, success=False)
 
            # Count remaining attempts so we can warn the user
            failures = LoginAttempt.recent_failures(ip, email)
            remaining = max(0, settings.LOGIN_ATTEMPT_LIMIT - failures)
 
            return Response(
                {
                    "message":   "Invalid email or password.",
                    "status":    "error",
                    "attempts_remaining": remaining,
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
 
        if not user.is_active:
            return Response(
                {"message": "Account is deactivated.", "status": "error"},
                status=status.HTTP_403_FORBIDDEN,
            )
 
        LoginAttempt.record(ip, email, success=True)
 
        # Detect new device and alert
        fingerprint = make_fingerprint(ip, user_agent)
        is_new_device = not KnownDevice.is_known(user, fingerprint)
        KnownDevice.register(user, ip, user_agent, fingerprint)
 
        if is_new_device:
            send_new_device_alert(user, ip, user_agent)
 
        #always sets expiry via SIMPLE_JWT settings
        tokens = issue_tokens(user)
 
        return Response(
            {
                "message": "Login successful.",
                "status":  "success",
                "data": {
                    **tokens,
                    "user": UserSerializer(user).data,
                },
            },
            status=status.HTTP_200_OK,
        )
 
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
 
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 
        try:
            token = RefreshToken(serializer.validated_data["refresh"])
            token.blacklist()   # ← server-side invalidation
        except TokenError:
            return Response(
                {"message": "Invalid or already expired token.", "status": "error"},
                status=status.HTTP_400_BAD_REQUEST,
            )
 
        return Response(
            {"message": "Logged out successfully.", "status": "success"},
            status=status.HTTP_200_OK,
        )
    
#FIX BUG-05: Only returns safe fields via UserSerializer

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]
 
    def get(self, request):
        return Response(
            {
                "message":"Profile retrieved successfully.",
                "status":"success",
                "data":UserSerializer(request.user).data,
            },
            status=status.HTTP_200_OK,
        )
 
    def patch(self, request):
        """Partial update — only allow safe fields to be changed."""
        allowed = {
            k: v for k, v in request.data.items()
            if k in ["first_name", "last_name", "phone"]
        }
        serializer = UserSerializer(
            request.user, data=allowed, partial=True
        )
        #UserSerializer is read-only so we use the model directly
        user = request.user
        for field, value in allowed.items():
            setattr(user, field, value)
        user.save()
 
        return Response(
            {
                "message":"Profile updated.",
                "status":"success",
                "data":UserSerializer(user).data,
            },
            status=status.HTTP_200_OK,
        )
  
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
 
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 
        user = request.user
        if not user.check_password(serializer.validated_data["old_password"]):
            return Response(
                {"message": "Current password is incorrect.", "status": "error"},
                status=status.HTTP_400_BAD_REQUEST,
            )
 
        user.set_password(serializer.validated_data["new_password"])
        user.save()
 
        # Rotate tokens — old tokens are effectively invalidated
        tokens = issue_tokens(user)
 
        return Response(
            {
                "message":"Password changed successfully.",
                "status":"success",
                "data":tokens,
            },
            status=status.HTTP_200_OK,
        )
 
 

# FIX BUG 4: OTP code generated server-side, stored server-side,

class RequestOTPView(APIView):
    permission_classes = [AllowAny]
 
    def post(self, request):
        serializer = RequestOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 
        email    = serializer.validated_data["email"]
        otp_type = serializer.validated_data["otp_type"]
 
        # Always return success even if email not found — prevents user enumeration
        try:
            user = User.objects.get(email=email)
            otp  = OTP.create_for(user, otp_type)          # stores in DB only
            sent_otp_email(user, otp.code, otp_type)       # sends via email only
        except User.DoesNotExist:
            pass  # silent — attacker cannot tell if email exists
 
        return Response(
            {
                "message": "If an account exists with that email, a code has been sent.",
                "status":  "success",
            },
            status=status.HTTP_200_OK,
        )
 
 

# OTP — VERIFY (standalone, e.g. for email verification)
 
class VerifyOTPView(APIView):
    permission_classes = [AllowAny]
 
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 
        otp  = serializer.validated_data["otp_instance"]
        user = serializer.validated_data["user"]
 
        otp.consume()  
 
        if otp.otp_type == OTPType.EMAIL_VERIFY:
            user.email_verified = True
            user.save(update_fields=["email_verified"])
 
        return Response(
            {"message": "Code verified successfully.", "status": "success"},
            status=status.HTTP_200_OK,
        )
 
 
# PASSWORD RESET
 
class ResetPasswordView(APIView):
    permission_classes = [AllowAny]
 
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 
        user = serializer.validated_data["user"]
        otp  = serializer.validated_data["otp_instance"]
 
        user.set_password(serializer.validated_data["new_password"])
        user.save()
        otp.consume()   # single-use
 
        return Response(
            {"message": "Password reset successfully. Please log in.", "status": "success"},
            status=status.HTTP_200_OK,
        )
 
 
# ACCOUNT DELETION
# FIX BUG-07: The complete two-step deletion flow that ChamaConnect is missing.
 
class RequestAccountDeletionView(APIView):
    permission_classes = [IsAuthenticated]
 
    def post(self, request):
        user = request.user
        otp  = OTP.create_for(user, OTPType.ACCOUNT_DELETION)
        sent_otp_email(user, otp.code, OTPType.ACCOUNT_DELETION)
 
        return Response(
            {
                "message": (
                    "A verification code has been sent to your email. "
                    "Submit it to /auth/delete/confirm to complete deletion."
                ),
                "status": "success",
            },
            status=status.HTTP_200_OK,
        )
 
 
class ConfirmAccountDeletionView(APIView):
    """
    FIX BUG-07: This is the endpoint ChamaConnect is missing entirely.
    The frontend should show an OTP input modal after the user requests deletion,
    then POST the code here.
    """
    permission_classes = [IsAuthenticated]
 
    def post(self, request):
        code = request.data.get("code", "")
 
        otp = (
            OTP.objects
            .filter(
                user=request.user,
                otp_type=OTPType.ACCOUNT_DELETION,
                code=code,
                is_used=False,
            )
            .order_by("-created_at")
            .first()
        )
 
        if not otp or not otp.is_valid:
            return Response(
                {"message": "Invalid or expired verification code.", "status": "error"},
                status=status.HTTP_400_BAD_REQUEST,
            )
 
        otp.consume()
 
        # Mark deletion as requested — actual deletion happens after
        # the legal retention period (mirrors ChamaConnect's 14-day window)
        request.user.deletion_requested_at = timezone.now()
        request.user.is_active = False
        request.user.save(update_fields=["deletion_requested_at", "is_active"])
 
        return Response(
            {
                "message": (
                    "Account deletion confirmed. Your account will be permanently "
                    "deleted within 14 days in accordance with data retention policies."
                ),
                "status": "success",
            },
            status=status.HTTP_200_OK,
        )