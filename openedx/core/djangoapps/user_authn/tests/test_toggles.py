"""
Tests for user_authn toggles and 2FA platform configuration.
"""

from unittest.mock import patch

from django.conf import settings
from django.test import TestCase, override_settings
from edx_toggles.toggles.testutils import override_waffle_switch

from openedx.core.djangoapps.user_authn.config.waffle import (
    ENABLE_STAFF_2FA as WAFFLE_ENABLE_STAFF_2FA,
    ENFORCE_STAFF_2FA_SETUP as WAFFLE_ENFORCE_STAFF_2FA_SETUP,
)
from openedx.core.djangoapps.user_authn.toggles import (
    is_staff_2fa_enabled,
    is_staff_2fa_setup_enforced,
)


class TestStaff2FAToggles(TestCase):
    """
    Tests for 2FA toggles and waffle switches.
    """

    def test_staff_2fa_enabled_default_off(self):
        """
        Verify that 2FA for staff defaults safely to False (off).
        """
        with override_settings(ENABLE_STAFF_2FA=False, FEATURES={'ENABLE_STAFF_2FA': False}):
            assert not is_staff_2fa_enabled()

    @override_settings(ENABLE_STAFF_2FA=True)
    def test_staff_2fa_enabled_via_django_setting(self):
        """
        Verify that 2FA is enabled when ENABLE_STAFF_2FA Django setting is True.
        """
        assert is_staff_2fa_enabled()

    def test_staff_2fa_enabled_via_features_dict(self):
        """
        Verify that 2FA is enabled when FEATURES['ENABLE_STAFF_2FA'] is True.
        """
        with override_settings(FEATURES={'ENABLE_STAFF_2FA': True}):
            assert is_staff_2fa_enabled()

    def test_staff_2fa_enabled_via_waffle_switch(self):
        """
        Verify that 2FA is enabled when user_authn.enable_staff_2fa waffle switch is active.
        """
        with override_settings(ENABLE_STAFF_2FA=False, FEATURES={'ENABLE_STAFF_2FA': False}):
            with override_waffle_switch(WAFFLE_ENABLE_STAFF_2FA, True):
                assert is_staff_2fa_enabled()

    def test_staff_2fa_setup_enforced_default_off(self):
        """
        Verify that 2FA setup enforcement defaults safely to False (off).
        """
        with override_settings(ENFORCE_STAFF_2FA_SETUP=False, FEATURES={'ENFORCE_STAFF_2FA_SETUP': False}):
            assert not is_staff_2fa_setup_enforced()

    @override_settings(ENFORCE_STAFF_2FA_SETUP=True)
    def test_staff_2fa_setup_enforced_via_django_setting(self):
        """
        Verify that setup enforcement is active when ENFORCE_STAFF_2FA_SETUP Django setting is True.
        """
        assert is_staff_2fa_setup_enforced()

    def test_staff_2fa_setup_enforced_via_features_dict(self):
        """
        Verify that setup enforcement is active when FEATURES['ENFORCE_STAFF_2FA_SETUP'] is True.
        """
        with override_settings(FEATURES={'ENFORCE_STAFF_2FA_SETUP': True}):
            assert is_staff_2fa_setup_enforced()

    def test_staff_2fa_setup_enforced_via_waffle_switch(self):
        """
        Verify that setup enforcement is active when user_authn.enforce_staff_2fa_setup waffle switch is active.
        """
        with override_settings(ENFORCE_STAFF_2FA_SETUP=False, FEATURES={'ENFORCE_STAFF_2FA_SETUP': False}):
            with override_waffle_switch(WAFFLE_ENFORCE_STAFF_2FA_SETUP, True):
                assert is_staff_2fa_setup_enforced()


class TestPlatformOTPConfiguration(TestCase):
    """
    Tests to verify django_otp apps and OTPMiddleware configurations in settings.
    """

    def test_django_otp_apps_installed(self):
        """
        Verify django_otp and its plugins are in INSTALLED_APPS.
        """
        assert 'django_otp' in settings.INSTALLED_APPS
        assert 'django_otp.plugins.otp_totp' in settings.INSTALLED_APPS
        assert 'django_otp.plugins.otp_static' in settings.INSTALLED_APPS

    def test_otp_middleware_configured_after_auth_middleware(self):
        """
        Verify OTPMiddleware is present in MIDDLEWARE and placed after CacheBackedAuthenticationMiddleware.
        """
        middleware_list = list(settings.MIDDLEWARE)
        assert 'django_otp.middleware.OTPMiddleware' in middleware_list
        assert 'openedx.core.djangoapps.cache_toolbox.middleware.CacheBackedAuthenticationMiddleware' in middleware_list

        auth_index = middleware_list.index(
            'openedx.core.djangoapps.cache_toolbox.middleware.CacheBackedAuthenticationMiddleware'
        )
        otp_index = middleware_list.index('django_otp.middleware.OTPMiddleware')
        assert otp_index > auth_index

    def test_cms_settings_otp_configuration(self):
        """
        Verify that CMS common settings also configure django_otp apps and OTPMiddleware correctly.
        """
        import cms.envs.common as cms_common

        assert 'django_otp' in cms_common.INSTALLED_APPS
        assert 'django_otp.plugins.otp_totp' in cms_common.INSTALLED_APPS
        assert 'django_otp.plugins.otp_static' in cms_common.INSTALLED_APPS

        cms_middleware = list(cms_common.MIDDLEWARE)
        assert 'django_otp.middleware.OTPMiddleware' in cms_middleware
        assert 'openedx.core.djangoapps.cache_toolbox.middleware.CacheBackedAuthenticationMiddleware' in cms_middleware

        cms_auth_idx = cms_middleware.index(
            'openedx.core.djangoapps.cache_toolbox.middleware.CacheBackedAuthenticationMiddleware'
        )
        cms_otp_idx = cms_middleware.index('django_otp.middleware.OTPMiddleware')
        assert cms_otp_idx > cms_auth_idx

        assert cms_common.ENABLE_STAFF_2FA is False
        assert cms_common.ENFORCE_STAFF_2FA_SETUP is False
