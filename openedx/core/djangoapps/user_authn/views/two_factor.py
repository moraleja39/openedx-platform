"""
Views for Staff Two-Factor Authentication (2FA) verification and device enrollment.
"""

import base64
import io
import logging
from urllib.parse import quote_plus

import qrcode
from django.conf import settings
from django.contrib.auth import login as django_login
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.translation import gettext as _
from django.views.generic import View
from django_otp import login as otp_login, match_token, user_has_device
from django_otp.plugins.otp_totp.models import TOTPDevice

from common.djangoapps.edxmako.shortcuts import render_to_response
from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers
from openedx.core.djangoapps.user_authn.cookies import set_logged_in_cookies
from openedx.core.djangoapps.user_authn.toggles import is_staff_2fa_enabled
from openedx.core.djangoapps.user_authn.utils import is_safe_login_or_logout_redirect
from openedx.core.djangoapps.user_authn.views.login import _handle_successful_authentication_and_login

log = logging.getLogger(__name__)

MAX_OTP_ATTEMPTS = 5


def _is_json_request(request):
    """
    Check if the incoming request expects a JSON response.
    """
    return (
        request.headers.get("x-requested-with") == "XMLHttpRequest"
        or "application/json" in request.headers.get("accept", "")
        or request.content_type == "application/json"
    )


def _get_staff_user(request):
    """
    Retrieve the staff user either from an active authenticated session or
    the pre-auth session key stored during partial login.
    """
    if request.user.is_authenticated and request.user.is_staff:
        return request.user

    user_id = request.session.get("pre_auth_staff_user_id")
    if user_id:
        try:
            user = User.objects.get(id=user_id, is_active=True, is_staff=True)
            user.backend = (
                request.session.get("pre_auth_staff_backend")
                or getattr(user, "backend", None)
                or settings.AUTHENTICATION_BACKENDS[0]
            )
            return user
        except User.DoesNotExist:
            log.warning(f"Pre-auth staff user id {user_id} does not exist or is inactive.")
            return None
    return None


def _get_safe_next_url(request, candidate_url=None):
    """
    Validate and return candidate next URL or default to /admin.
    """
    url = candidate_url or request.GET.get("next") or request.POST.get("next") or request.session.get("pre_auth_staff_next_url") or "/admin"
    if not is_safe_login_or_logout_redirect(url, request.get_host(), None, request.is_secure()):
        url = "/admin"
    return url


class TwoFactorVerifyView(View):
    """
    View for verifying a 6-digit TOTP token or static backup token for staff users.
    """

    def get(self, request, *args, **kwargs):
        if not is_staff_2fa_enabled():
            return redirect(_get_safe_next_url(request))

        user = _get_staff_user(request)
        if not user:
            return redirect("/login")

        # If user is already authenticated and verified by OTP middleware, proceed
        if request.user.is_authenticated and getattr(request.user, "is_verified", lambda: False)():
            return redirect(_get_safe_next_url(request))

        # If user has no confirmed device, redirect to enrollment
        if not user_has_device(user):
            next_url = _get_safe_next_url(request)
            return redirect(f"{reverse('two_factor_setup')}?next={quote_plus(next_url)}")

        next_url = _get_safe_next_url(request)
        context = {
            "post_url": request.path,
            "next_url": next_url,
            "error": None,
            "can_setup": True,
            "setup_url": f"{reverse('two_factor_setup')}?next={quote_plus(next_url)}",
        }
        return render_to_response("student_account/two_factor_verify.html", context)

    def post(self, request, *args, **kwargs):
        if not is_staff_2fa_enabled():
            return redirect(_get_safe_next_url(request))

        user = _get_staff_user(request)
        if not user:
            if _is_json_request(request):
                return JsonResponse({"error": _("Session expired. Please log in again."), "error_code": "session-expired"}, status=400)
            return redirect("/login")

        # Rate-limiting check on failed attempts
        failed_attempts = request.session.get("otp_failed_attempts", 0)
        if failed_attempts >= MAX_OTP_ATTEMPTS:
            error_msg = _("Too many failed attempts. Please try again later.")
            if _is_json_request(request):
                return JsonResponse({"error": error_msg, "error_code": "rate-limited"}, status=429)
            next_url = _get_safe_next_url(request)
            return render_to_response(
                "student_account/two_factor_verify.html",
                {
                    "post_url": request.path,
                    "next_url": next_url,
                    "error": error_msg,
                    "can_setup": False,
                    "setup_url": reverse("two_factor_setup"),
                },
            )

        token = request.POST.get("otp_token") or request.POST.get("token") or ""
        token = str(token).strip().replace(" ", "")

        device = match_token(user, token) if token else None

        if device is not None:
            # Clear pre-auth state & failures
            request.session.pop("otp_failed_attempts", None)
            request.session.pop("pre_auth_staff_user_id", None)
            request.session.pop("pre_auth_staff_backend", None)
            next_url = _get_safe_next_url(request)
            request.session.pop("pre_auth_staff_next_url", None)

            # Establish authenticated and OTP session
            _handle_successful_authentication_and_login(user, request)
            otp_login(request, device)

            if _is_json_request(request):
                response = JsonResponse({"success": True, "redirect_url": next_url})
            else:
                response = HttpResponseRedirect(next_url)

            response = set_logged_in_cookies(request, response, user)
            return response
        else:
            request.session["otp_failed_attempts"] = failed_attempts + 1
            error_msg = _("Invalid authentication code. Please try again.")
            if _is_json_request(request):
                return JsonResponse({"error": error_msg, "error_code": "invalid-token"}, status=400)

            next_url = _get_safe_next_url(request)
            return render_to_response(
                "student_account/two_factor_verify.html",
                {
                    "post_url": request.path,
                    "next_url": next_url,
                    "error": error_msg,
                    "can_setup": True,
                    "setup_url": f"{reverse('two_factor_setup')}?next={quote_plus(next_url)}",
                },
            )


class TwoFactorSetupView(View):
    """
    View for enrolling a new TOTP authenticator device with QR code rendering.
    """

    def _generate_qr_data_uri(self, device):
        """
        Generate base64 data URI of the QR code for a given TOTP device.
        """
        otpauth_url = device.config_url
        img = qrcode.make(otpauth_url)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_code_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        return f"data:image/png;base64,{qr_code_b64}"

    def _format_secret_key(self, device):
        """
        Format hex key into standard base32 string grouped in 4 characters for readability.
        """
        try:
            raw_bytes = bytes.fromhex(device.key)
            b32_str = base64.b32encode(raw_bytes).decode("utf-8").rstrip("=")
            return " ".join(b32_str[i:i + 4] for i in range(0, len(b32_str), 4))
        except Exception:
            return device.key

    def get(self, request, *args, **kwargs):
        if not is_staff_2fa_enabled():
            return redirect(_get_safe_next_url(request))

        user = _get_staff_user(request)
        if not user:
            return redirect("/login")

        # Get or create an unconfirmed TOTPDevice for enrollment
        device = TOTPDevice.objects.filter(user=user, confirmed=False).order_by("-id").first()
        if not device:
            device = TOTPDevice.objects.create(user=user, name="default", confirmed=False)

        qr_code_data_uri = self._generate_qr_data_uri(device)
        secret_key = self._format_secret_key(device)
        next_url = _get_safe_next_url(request)

        context = {
            "post_url": request.path,
            "next_url": next_url,
            "qr_code_data_uri": qr_code_data_uri,
            "secret_key": secret_key,
            "error": None,
        }
        return render_to_response("student_account/two_factor_setup.html", context)

    def post(self, request, *args, **kwargs):
        if not is_staff_2fa_enabled():
            return redirect(_get_safe_next_url(request))

        user = _get_staff_user(request)
        if not user:
            if _is_json_request(request):
                return JsonResponse({"error": _("Session expired. Please log in again."), "error_code": "session-expired"}, status=400)
            return redirect("/login")

        device = TOTPDevice.objects.filter(user=user, confirmed=False).order_by("-id").first()
        if not device:
            return redirect(request.path)

        token = request.POST.get("otp_token") or request.POST.get("token") or ""
        token = str(token).strip().replace(" ", "")

        if token and device.verify_token(token):
            # Remove any previous confirmed TOTP devices to avoid device proliferation
            TOTPDevice.objects.filter(user=user, confirmed=True).delete()
            device.confirmed = True
            device.save()

            # Clean up other pending unconfirmed devices
            TOTPDevice.objects.filter(user=user, confirmed=False).exclude(id=device.id).delete()

            # Clear pre-auth state
            request.session.pop("otp_failed_attempts", None)
            request.session.pop("pre_auth_staff_user_id", None)
            request.session.pop("pre_auth_staff_backend", None)
            next_url = _get_safe_next_url(request)
            request.session.pop("pre_auth_staff_next_url", None)

            # Establish session & OTP verification
            _handle_successful_authentication_and_login(user, request)
            otp_login(request, device)

            if _is_json_request(request):
                response = JsonResponse({"success": True, "redirect_url": next_url})
            else:
                response = HttpResponseRedirect(next_url)

            response = set_logged_in_cookies(request, response, user)
            return response
        else:
            error_msg = _("Invalid verification code. Please make sure your device clock is synchronized and try again.")
            if _is_json_request(request):
                return JsonResponse({"error": error_msg, "error_code": "invalid-token"}, status=400)

            qr_code_data_uri = self._generate_qr_data_uri(device)
            secret_key = self._format_secret_key(device)
            next_url = _get_safe_next_url(request)

            context = {
                "post_url": request.path,
                "next_url": next_url,
                "qr_code_data_uri": qr_code_data_uri,
                "secret_key": secret_key,
                "error": error_msg,
            }
            return render_to_response("student_account/two_factor_setup.html", context)
