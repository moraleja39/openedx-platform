"""
Toggles for user_authn
"""


from django.conf import settings

from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers
from openedx.core.djangoapps.theming.helpers import get_current_request
from openedx.core.djangoapps.user_authn.config import waffle as authn_waffle


def is_require_third_party_auth_enabled():
    # TODO: Replace function with SettingToggle when it is available.
    return getattr(settings, "ENABLE_REQUIRE_THIRD_PARTY_AUTH", False)


def should_redirect_to_authn_microfrontend():
    """
    Checks if login/registration should be done via MFE.
    """
    request = get_current_request()
    if request and request.GET.get('skip_authn_mfe'):
        return False
    return configuration_helpers.get_value(
        'ENABLE_AUTHN_MICROFRONTEND', settings.FEATURES.get('ENABLE_AUTHN_MICROFRONTEND')
    )


# .. toggle_name: ENABLE_AUTO_GENERATED_USERNAME
# .. toggle_implementation: DjangoSetting
# .. toggle_default: False
# .. toggle_description: Set to True to enable auto-generation of usernames.
# .. toggle_use_cases: open_edx
# .. toggle_creation_date: 2024-02-20
# .. toggle_warning: Changing this setting may affect user authentication, account management and discussions experience.


def is_auto_generated_username_enabled():
    """
    Checks if auto-generated username should be enabled.
    """
    return configuration_helpers.get_value(
        'ENABLE_AUTO_GENERATED_USERNAME', settings.FEATURES.get('ENABLE_AUTO_GENERATED_USERNAME')
    )


# .. toggle_name: ENABLE_STAFF_2FA
# .. toggle_implementation: DjangoSetting
# .. toggle_default: False
# .. toggle_description: Set to True to enforce Two-Factor Authentication (TOTP 2FA) for staff users.
# .. toggle_use_cases: open_edx
# .. toggle_creation_date: 2026-10-07


def is_staff_2fa_enabled():
    """
    Checks if Two-Factor Authentication (2FA) is enabled for staff users.
    Returns True if either the user_authn.enable_staff_2fa waffle switch or
    ENABLE_STAFF_2FA setting is enabled.
    """
    if authn_waffle.ENABLE_STAFF_2FA.is_enabled():
        return True
    feature_setting = getattr(settings, 'ENABLE_STAFF_2FA', False) or settings.FEATURES.get('ENABLE_STAFF_2FA', False)
    return configuration_helpers.get_value(
        'ENABLE_STAFF_2FA',
        feature_setting
    )


# .. toggle_name: ENFORCE_STAFF_2FA_SETUP
# .. toggle_implementation: DjangoSetting
# .. toggle_default: False
# .. toggle_description: Set to True to enforce 2FA device setup during staff login for users without devices.
# .. toggle_use_cases: open_edx
# .. toggle_creation_date: 2026-10-07


def is_staff_2fa_setup_enforced():
    """
    Checks if 2FA device setup is enforced during staff login for users without devices.
    Returns True if either the user_authn.enforce_staff_2fa_setup waffle switch or
    ENFORCE_STAFF_2FA_SETUP setting is enabled.
    """
    if authn_waffle.ENFORCE_STAFF_2FA_SETUP.is_enabled():
        return True
    feature_setting = (
        getattr(settings, 'ENFORCE_STAFF_2FA_SETUP', False)
        or settings.FEATURES.get('ENFORCE_STAFF_2FA_SETUP', False)
    )
    return configuration_helpers.get_value(
        'ENFORCE_STAFF_2FA_SETUP',
        feature_setting
    )
