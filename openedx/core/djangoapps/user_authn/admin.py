"""
Django Admin site customization for Two-Factor Authentication (OTP).
"""

from django.contrib import admin
from django_otp.admin import OTPAdminSite as BaseOTPAdminSite

from openedx.core.djangoapps.user_authn.toggles import is_staff_2fa_enabled


class OTPAdminSite(BaseOTPAdminSite):
    """
    An OTPAdminSite subclass that respects the platform's staff 2FA feature toggle.

    When staff 2FA is enabled (via settings or Waffle toggle), staff users must
    be OTP verified (user.is_verified() == True) to access the Django admin site.
    When staff 2FA is disabled, standard Django Admin staff permissions apply.
    """

    def has_permission(self, request):
        if not super(BaseOTPAdminSite, self).has_permission(request):
            return False
        if is_staff_2fa_enabled():
            return getattr(request.user, "is_verified", lambda: False)()
        return True


def patch_admin_site_with_otp():
    """
    Ensure the default admin.site is wrapped or patched with OTPAdminSite.
    """
    if not isinstance(admin.site, BaseOTPAdminSite):
        admin.site.__class__ = OTPAdminSite
