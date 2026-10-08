"""
Tests for Staff Two-Factor Authentication (2FA) verification, setup, and admin protection.
"""

from unittest.mock import patch
from urllib.parse import quote_plus

from django.conf import settings
from django.contrib.auth.models import AnonymousUser, User
from django.test import RequestFactory, TestCase
from django.test.utils import override_settings
from django.urls import reverse
from django_otp import DEVICE_ID_SESSION_KEY
from django_otp.plugins.otp_static.models import StaticDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from edx_toggles.toggles.testutils import override_waffle_switch

from common.djangoapps.student.tests.factories import UserFactory
from openedx.core.djangoapps.user_authn.admin import OTPAdminSite, patch_admin_site_with_otp
from openedx.core.djangoapps.user_authn.config.waffle import ENABLE_STAFF_2FA
from openedx.core.djangoapps.user_authn.views.two_factor import TwoFactorSetupView, TwoFactorVerifyView


class TwoFactorViewsTest(TestCase):
    """
    Unit and integration tests for TwoFactorVerifyView and TwoFactorSetupView.
    """

    def setUp(self):
        super().setUp()
        self.password = "staffpassword123"
        self.staff_user = UserFactory.create(
            username="staff_user",
            email="staff@example.com",
            is_staff=True,
            is_active=True,
        )
        self.staff_user.set_password(self.password)
        self.staff_user.save()

        self.learner_user = UserFactory.create(
            username="learner_user",
            email="learner@example.com",
            is_staff=False,
            is_active=True,
        )
        self.learner_user.set_password(self.password)
        self.learner_user.save()

        self.factory = RequestFactory()
        self.verify_url = reverse("two_factor_verify")
        self.setup_url = reverse("two_factor_setup")

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_verify_get_redirects_to_login_if_no_session(self):
        """If no pre-auth session and not logged in, GET /login/2fa/ redirects to /login."""
        response = self.client.get(self.verify_url)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/login")

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_verify_get_redirects_to_setup_if_no_confirmed_device(self):
        """If staff user has no confirmed device, GET /login/2fa/ redirects to setup."""
        session = self.client.session
        session["pre_auth_staff_user_id"] = self.staff_user.id
        session["pre_auth_staff_next_url"] = "/admin"
        session.save()

        response = self.client.get(self.verify_url)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(self.setup_url))

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_verify_get_renders_page_with_confirmed_device(self):
        """If staff user has a confirmed device, GET /login/2fa/ renders verification page without setup link."""
        TOTPDevice.objects.create(user=self.staff_user, name="default", confirmed=True)

        session = self.client.session
        session["pre_auth_staff_user_id"] = self.staff_user.id
        session.save()

        response = self.client.get(self.verify_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Set up or reconfigure authenticator app")
        self.assertNotContains(response, self.setup_url)

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_setup_get_redirects_to_verify_if_user_already_has_confirmed_device(self):
        """Pre-auth staff user who already has an enrolled device cannot access setup GET."""
        TOTPDevice.objects.create(user=self.staff_user, name="default", confirmed=True)

        session = self.client.session
        session["pre_auth_staff_user_id"] = self.staff_user.id
        session["pre_auth_staff_next_url"] = "/admin"
        session.save()

        response = self.client.get(self.setup_url)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(self.verify_url))

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_setup_post_rejected_if_user_already_has_confirmed_device(self):
        """Pre-auth staff user who already has an enrolled device cannot overwrite or enroll new device."""
        existing_device = TOTPDevice.objects.create(user=self.staff_user, name="default", confirmed=True)
        unconfirmed_device = TOTPDevice.objects.create(user=self.staff_user, name="new_device", confirmed=False)

        session = self.client.session
        session["pre_auth_staff_user_id"] = self.staff_user.id
        session.save()

        with patch.object(TOTPDevice, "verify_token", return_value=True):
            response = self.client.post(
                self.setup_url,
                {"otp_token": "123456"},
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )

        self.assertEqual(response.status_code, 403)
        existing_device.refresh_from_db()
        self.assertTrue(existing_device.confirmed)
        unconfirmed_device.refresh_from_db()
        self.assertFalse(unconfirmed_device.confirmed)

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_setup_get_allowed_for_authenticated_verified_staff_user(self):
        """Fully authenticated and OTP-verified staff member can access setup to reconfigure device."""
        device = TOTPDevice.objects.create(user=self.staff_user, name="default", confirmed=True)
        self.client.login(username=self.staff_user.username, password=self.password)

        session = self.client.session
        session[DEVICE_ID_SESSION_KEY] = device.persistent_id
        session.save()

        response = self.client.get(self.setup_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Save Backup Recovery Codes")

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_verify_post_valid_totp_token_success(self):
        """Submitting a valid TOTP code logs the staff user in and redirects to next URL."""
        device = TOTPDevice.objects.create(user=self.staff_user, name="default", confirmed=True)

        session = self.client.session
        session["pre_auth_staff_user_id"] = self.staff_user.id
        session["pre_auth_staff_next_url"] = "/admin"
        session.save()

        with patch.object(TOTPDevice, "verify_token", return_value=True):
            response = self.client.post(self.verify_url, {"otp_token": "123456", "next": "/admin"})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/admin")
        self.assertNotIn("pre_auth_staff_user_id", self.client.session)
        # Check user is logged in
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.staff_user.id)

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_verify_post_valid_static_backup_token_success(self):
        """Staff user can authenticate using a static recovery backup token."""
        static_device = StaticDevice.objects.create(user=self.staff_user, name="backup", confirmed=True)
        token = static_device.token_set.create(token="backup123456")

        session = self.client.session
        session["pre_auth_staff_user_id"] = self.staff_user.id
        session.save()

        response = self.client.post(self.verify_url, {"otp_token": "backup123456", "next": "/admin"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/admin")
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.staff_user.id)

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_verify_post_invalid_token_error(self):
        """Submitting an invalid code fails and increments rate-limiting counter."""
        TOTPDevice.objects.create(user=self.staff_user, name="default", confirmed=True)

        session = self.client.session
        session["pre_auth_staff_user_id"] = self.staff_user.id
        session.save()

        with patch.object(TOTPDevice, "verify_token", return_value=False):
            response = self.client.post(self.verify_url, {"otp_token": "000000"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.session.get("otp_failed_attempts"), 1)
        self.assertNotIn("_auth_user_id", self.client.session)

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_verify_post_rate_limiting(self):
        """Exceeding max failed OTP attempts blocks further token submissions."""
        TOTPDevice.objects.create(user=self.staff_user, name="default", confirmed=True)

        session = self.client.session
        session["pre_auth_staff_user_id"] = self.staff_user.id
        session["otp_failed_attempts"] = 5
        session.save()

        response = self.client.post(
            self.verify_url,
            {"otp_token": "123456"},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 429)

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_setup_get_generates_qr_code_and_unconfirmed_device(self):
        """GET /account/2fa/setup/ creates an unconfirmed TOTP device, backup tokens, and provides QR data URI."""
        session = self.client.session
        session["pre_auth_staff_user_id"] = self.staff_user.id
        session.save()

        response = self.client.get(self.setup_url)
        self.assertEqual(response.status_code, 200)

        device = TOTPDevice.objects.filter(user=self.staff_user, confirmed=False).first()
        self.assertIsNotNone(device)

        static_device = StaticDevice.objects.filter(user=self.staff_user, confirmed=False).first()
        self.assertIsNotNone(static_device)
        self.assertEqual(static_device.token_set.count(), 8)
        self.assertContains(response, "Save Backup Recovery Codes")

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_setup_post_confirmation_success(self):
        """Submitting matching code activates TOTP device, confirms backup static device, clears pre-auth, and logs user in."""
        device = TOTPDevice.objects.create(user=self.staff_user, name="default", confirmed=False)
        static_device = StaticDevice.objects.create(user=self.staff_user, name="backup", confirmed=False)
        static_device.token_set.create(token="recov123")

        session = self.client.session
        session["pre_auth_staff_user_id"] = self.staff_user.id
        session["pre_auth_staff_next_url"] = "/admin"
        session.save()

        with patch.object(TOTPDevice, "verify_token", return_value=True):
            response = self.client.post(self.setup_url, {"otp_token": "654321", "next": "/admin"})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/admin")

        device.refresh_from_db()
        self.assertTrue(device.confirmed)
        static_device.refresh_from_db()
        self.assertTrue(static_device.confirmed)
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.staff_user.id)

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_setup_post_confirmation_failure(self):
        """Submitting invalid confirmation code leaves device unconfirmed."""
        device = TOTPDevice.objects.create(user=self.staff_user, name="default", confirmed=False)

        session = self.client.session
        session["pre_auth_staff_user_id"] = self.staff_user.id
        session.save()

        with patch.object(TOTPDevice, "verify_token", return_value=False):
            response = self.client.post(self.setup_url, {"otp_token": "000000"})

        self.assertEqual(response.status_code, 200)
        device.refresh_from_db()
        self.assertFalse(device.confirmed)
        self.assertNotIn("_auth_user_id", self.client.session)

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    @override_settings(AUTHENTICATION_BACKENDS=[
        "django.contrib.auth.backends.ModelBackend",
        "common.djangoapps.student.models.EmailAuthBackend",
    ])
    def test_setup_post_confirmation_success_with_multiple_backends(self):
        """Device enrollment succeeds when multiple auth backends are configured and backend is in session."""
        device = TOTPDevice.objects.create(user=self.staff_user, name="default", confirmed=False)

        session = self.client.session
        session["pre_auth_staff_user_id"] = self.staff_user.id
        session["pre_auth_staff_backend"] = "common.djangoapps.student.models.EmailAuthBackend"
        session["pre_auth_staff_next_url"] = "/admin"
        session.save()

        with patch.object(TOTPDevice, "verify_token", return_value=True):
            response = self.client.post(self.setup_url, {"otp_token": "654321", "next": "/admin"})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/admin")

        device.refresh_from_db()
        self.assertTrue(device.confirmed)
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.staff_user.id)
        self.assertEqual(self.client.session["_auth_user_backend"], "common.djangoapps.student.models.EmailAuthBackend")
        self.assertNotIn("pre_auth_staff_backend", self.client.session)
        self.assertNotIn("pre_auth_staff_user_id", self.client.session)

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    @override_settings(AUTHENTICATION_BACKENDS=[
        "django.contrib.auth.backends.ModelBackend",
        "common.djangoapps.student.models.EmailAuthBackend",
    ])
    def test_setup_post_confirmation_success_with_fallback_backend(self):
        """Device enrollment succeeds with fallback backend when pre_auth_staff_backend is absent."""
        device = TOTPDevice.objects.create(user=self.staff_user, name="default", confirmed=False)

        session = self.client.session
        session["pre_auth_staff_user_id"] = self.staff_user.id
        session["pre_auth_staff_next_url"] = "/admin"
        session.save()

        with patch.object(TOTPDevice, "verify_token", return_value=True):
            response = self.client.post(self.setup_url, {"otp_token": "654321", "next": "/admin"})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/admin")

        device.refresh_from_db()
        self.assertTrue(device.confirmed)
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.staff_user.id)
        self.assertEqual(self.client.session["_auth_user_backend"], "django.contrib.auth.backends.ModelBackend")

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    @override_settings(AUTHENTICATION_BACKENDS=[
        "django.contrib.auth.backends.ModelBackend",
        "common.djangoapps.student.models.EmailAuthBackend",
    ])
    def test_verify_post_valid_totp_token_with_multiple_backends(self):
        """Verification succeeds when multiple auth backends are configured and backend is restored."""
        device = TOTPDevice.objects.create(user=self.staff_user, name="default", confirmed=True)

        session = self.client.session
        session["pre_auth_staff_user_id"] = self.staff_user.id
        session["pre_auth_staff_backend"] = "common.djangoapps.student.models.EmailAuthBackend"
        session["pre_auth_staff_next_url"] = "/admin"
        session.save()

        with patch.object(TOTPDevice, "verify_token", return_value=True):
            response = self.client.post(self.verify_url, {"otp_token": "123456", "next": "/admin"})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/admin")
        self.assertNotIn("pre_auth_staff_backend", self.client.session)
        self.assertNotIn("pre_auth_staff_user_id", self.client.session)
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.staff_user.id)
        self.assertEqual(self.client.session["_auth_user_backend"], "common.djangoapps.student.models.EmailAuthBackend")

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    @override_settings(AUTHENTICATION_BACKENDS=[
        "django.contrib.auth.backends.ModelBackend",
        "common.djangoapps.student.models.EmailAuthBackend",
    ])
    def test_verify_post_valid_totp_token_with_fallback_backend(self):
        """Verification succeeds with fallback backend when multiple backends are configured."""
        device = TOTPDevice.objects.create(user=self.staff_user, name="default", confirmed=True)

        session = self.client.session
        session["pre_auth_staff_user_id"] = self.staff_user.id
        session["pre_auth_staff_next_url"] = "/admin"
        session.save()

        with patch.object(TOTPDevice, "verify_token", return_value=True):
            response = self.client.post(self.verify_url, {"otp_token": "123456", "next": "/admin"})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/admin")
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.staff_user.id)
        self.assertEqual(self.client.session["_auth_user_backend"], "django.contrib.auth.backends.ModelBackend")


class OTPAdminSiteTest(TestCase):
    """
    Tests for OTPAdminSite permissions and toggle integration.
    """

    def setUp(self):
        super().setUp()
        self.admin_site = OTPAdminSite(name="test_otp_admin")
        self.factory = RequestFactory()

        self.staff_user = UserFactory.create(username="staff", is_staff=True, is_active=True)
        self.learner_user = UserFactory.create(username="learner", is_staff=False, is_active=True)

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_admin_permission_denied_for_unverified_staff_when_2fa_enabled(self):
        """Staff user without OTP verification is denied admin access when 2FA toggle is on."""
        request = self.factory.get("/admin/")
        request.user = self.staff_user
        request.user.is_verified = lambda: False

        self.assertFalse(self.admin_site.has_permission(request))

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_admin_permission_granted_for_verified_staff_when_2fa_enabled(self):
        """Staff user with OTP verification is granted admin access when 2FA toggle is on."""
        request = self.factory.get("/admin/")
        request.user = self.staff_user
        request.user.is_verified = lambda: True

        self.assertTrue(self.admin_site.has_permission(request))

    @override_waffle_switch(ENABLE_STAFF_2FA, active=True)
    def test_admin_permission_denied_for_non_staff_learner(self):
        """Non-staff learner is always denied admin access."""
        request = self.factory.get("/admin/")
        request.user = self.learner_user
        request.user.is_verified = lambda: True

        self.assertFalse(self.admin_site.has_permission(request))

    @override_waffle_switch(ENABLE_STAFF_2FA, active=False)
    @override_settings(ENABLE_STAFF_2FA=False)
    def test_admin_permission_granted_for_unverified_staff_when_2fa_disabled(self):
        """When 2FA toggle is disabled, staff user can access admin without OTP verification."""
        request = self.factory.get("/admin/")
        request.user = self.staff_user
        request.user.is_verified = lambda: False

        self.assertTrue(self.admin_site.has_permission(request))
