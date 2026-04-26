from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
import uuid


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password) # for password hashing

        user.save(using= self.db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_superuser(email, password, **extra_fields)
    
class User(AbstractBaseUser, PermissionsMixin):
    """
    This ensures sensitive data eg OTP and transactions live in their own models
    this is an added security level, plus FIXES BUG 5
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=200)
    phone = models.CharField(max_length=20, blank=True)

    #user account status
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)

    #audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    deletion_requested_at = models.DateTimeField(null=True, blank=True)
    deletion_completed_at = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    class Meta:
        db_table = "users"

    def __str__(self):
        return f"{self.first_name} {self.last_name} <{self.email}>"
    

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

"""
This is for the BUG 6 ,, here we record the login attempts and block 
based on specific ip and specific target account, ensuring brute-force login attempts 
are dealt with
"""

class LoginAttempt(models.Model):
    ip_address = models.GenericIPAddressField()
    email = models.EmailField()
    attempted_at = models.DateTimeField(auto_now_add=True)
    was_successful = models.BooleanField(default=False)

    class Meta:
        db_table = "login_attempts"
        indexes = [
            models.Index(fields=['ip_address','email','attempted_at']),
        ]

    def __str__(self):
        status = "OK" if self.was_successful else "FAILED"
        return f"[{status}] {self.email} from {self.ip_address} at {self.attempted_at}"
    
    @classmethod
    def recent_failures(cls, ip_address, email, window_minutes = 15):
        # count failed attempts for a specific ip_address within window_minutes
        # used by login view before processing credentials
        since = timezone.now() - timezone.timedelta(minutes=window_minutes)
        return cls.objects.filter(
            ip_address = ip_address,
            email=email,
            was_successful=False,
            attempted_at__gte=since,
        ).count()
    
    @classmethod
    def is_locked_out(cls, ip_address, email, max_attempts=5, window_minutes=15):
        return cls.recent_failures(ip_address, email, window_minutes) >= max_attempts
 
    @classmethod
    def record(cls, ip_address, email, success):
        cls.objects.create(
            ip_address=ip_address,
            email=email,
            was_successful=success,
        )
        # On successful login, clear the failure history for this combination
        if success:
            cls.objects.filter(
                ip_address=ip_address,
                email=email,
                was_successful=False,
            ).delete()

"""
Send new device login via email to confirm Login
FIX BUG 8
"""
class KnownDevice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="known_devices")
    ip_address      = models.GenericIPAddressField()
    user_agent      = models.TextField()
    fingerprint     = models.CharField(max_length=64, db_index=True)
    first_seen_at   = models.DateTimeField(auto_now_add=True)
    last_seen_at    = models.DateTimeField(auto_now=True)
 
    class Meta:
        db_table        = "known_devices"
        unique_together = [("user", "fingerprint")]
 
    def __str__(self):
        return f"{self.user.email} — {self.ip_address} (first seen {self.first_seen_at:%Y-%m-%d})"
    
    @classmethod
    def is_known(cls, user, fingerprint):
        return cls.objects.filter(user=user, fingerprint=fingerprint).exists()
    
    @classmethod
    def register(cls, user, ip_address, user_agent, fingerprint):
        obj, created = cls.objects.get_or_create(
            user=user,
            fingerprint=fingerprint,
            defaults={"ip_address": ip_address, "user_agent": user_agent},
        )
        if not created:
            obj.last_seen_at = timezone.now()
            obj.save(update_fields=["last_seen_at"])
        return created  # True = brand new device → trigger alert email
    
"""
FIX BUG 4 OTPs live on database server-side only
They are NEVER included in any API response. The client only ever
submits an OTP (it never receives one).
"""
class OTPType(models.TextChoices):
    PASSWORD_RESET   = "PASSWORD_RESET",   "Password Reset"
    ACCOUNT_DELETION = "ACCOUNT_DELETION", "Account Deletion"
    EMAIL_VERIFY     = "EMAIL_VERIFY",     "Email Verification"

class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="otps")
    otp_type = models.CharField(max_length=30, choices=OTPType.choices)
    code = models.CharField(max_length=6)   # the 6-digit code
    expires_at = models.DateTimeField() # hard expiry stored server-side
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "otps"
        indexes = [models.Index(fields=["user", "otp_type", "is_used"])]
    
    def __str__(self):
        return f"OTP({self.otp_type}) for {self.user.email} — {'used' if self.is_used else 'active'}"
 
    @property
    def is_expired(self):
        return timezone.now() > self.expires_at
 
    @property
    def is_valid(self):
        return not self.is_used and not self.is_expired
 
    def consume(self):
        """Mark OTP as used — single-use enforcement."""
        self.is_used = True
        self.save(update_fields=["is_used"])
 
    @classmethod
    def create_for(cls, user, otp_type, lifetime_minutes=30):
        import secrets

        # invalidate any previous used otps from the same user
        cls.objects.filter(
            user=user,
            otp_type=otp_type,
            is_used=False,
        ).update(is_used=True)
 
        code = str(secrets.randbelow(900000) + 100000)  # always 6 digits
        return cls.objects.create(
            user=user,
            otp_type=otp_type,
            code=code,
            expires_at=timezone.now() + timezone.timedelta(minutes=lifetime_minutes),
        )