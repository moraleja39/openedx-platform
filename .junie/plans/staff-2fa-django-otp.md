---
sessionId: session-261007-140636-sb4q
---

# Requirements

### Overview & Goals
The goal of this initiative is to ensure seamless Two-Factor Authentication (2FA / TOTP) in Open edX for staff users (`user.is_staff == True`), and specifically resolve the backend resolution issue encountered during 2FA enrollment (`ValueError: You have multiple authentication backends configured...`), while keeping the learner login pipeline completely unaffected.

### Feasibility & Complexity Assessment
- **Overall Complexity**: **Low** (Focused bug fix and defensive auth backend resolution).
- **Recommended Approach**: Persist the resolved authentication backend string in the pre-auth session state upon initial credential authentication in `login_user`, and restore `user.backend` when loading the pre-auth staff user in `two_factor.py` and `_handle_successful_authentication_and_login`.
- **Why this approach?**:
  - Django's `login()` requires either a `backend` argument or a `user.backend` attribute whenever multiple authentication backends are listed in `settings.AUTHENTICATION_BACKENDS`.
  - Storing the backend identifier during the pre-auth challenge preserves the authenticating provider (e.g. ModelBackend, RateLimitedBackend, SAML/SSO) through to final session creation after 2FA verification/setup.

### Scope
- **In Scope**:
  - Persisting `pre_auth_staff_backend` in session state during `login_user` staff 2FA interception.
  - Ensuring `_get_staff_user` in `two_factor.py` assigns `user.backend` from session (with fallback to `settings.AUTHENTICATION_BACKENDS[0]`).
  - Removing duplicate `django_login` calls in `TwoFactorVerifyView` and `TwoFactorSetupView` (leveraging `_handle_successful_authentication_and_login` followed by `otp_login`).
  - Adding defensive fallback in `_handle_successful_authentication_and_login` so `user.backend` is guaranteed to be set.
  - Adding multi-backend test coverage in `test_two_factor.py` to prevent regressions.
- **Out of Scope**:
  - Changing learner authentication flows or frontend MFE login logic.
  - Modifying OTP device verification algorithms or `django-otp` internals.

### User Stories
- **As a Staff User**, I want to enroll my 2FA authenticator device and verify my TOTP code without encountering backend configuration exceptions, so that I can complete login smoothly.
- **As a System Administrator**, I want 2FA session creation to work reliably in environments with multiple authentication backends (SSO, OAuth, email/password).

# Technical Design

### Current Implementation & Root Cause
- **Root Cause**: During staff login in `login_user` (`openedx/core/djangoapps/user_authn/views/login.py`), the staff user is intercepted for 2FA, saving only `pre_auth_staff_user_id` to the session.
- When the user visits `/account/2fa/setup/` or `/login/2fa/` (`openedx/core/djangoapps/user_authn/views/two_factor.py`), `_get_staff_user(request)` loads a fresh `User` model instance via `User.objects.get(id=user_id)`.
- Because this instance is fetched directly from the database rather than `authenticate()`, `user.backend` is not set.
- When `django_login(request, user)` or `_handle_successful_authentication_and_login(user, request)` runs, Django detects multiple `AUTHENTICATION_BACKENDS` (e.g. `RateLimitedBackend`, `ModelBackend`, `GoogleOAuth2`, `SAMLAuthBackend`) and raises `ValueError: You have multiple authentication backends configured and therefore must provide the backend argument or set the backend attribute on the user.`

### Key Decisions
1. **Pre-Auth Backend Preservation**:
   - *Decision*: Store `request.session['pre_auth_staff_backend'] = getattr(possibly_authenticated_user, 'backend', None) or settings.AUTHENTICATION_BACKENDS[0]` during staff interception in `login_user`.
   - *Rationale*: Guarantees that the exact backend that validated the user's password/credentials is retained across redirects.
2. **Defensive Backend Restoration in `_get_staff_user` & `_handle_successful_authentication_and_login`**:
   - *Decision*: Assign `user.backend = request.session.get('pre_auth_staff_backend') or getattr(user, 'backend', None) or settings.AUTHENTICATION_BACKENDS[0]` whenever loading the pre-auth user and prior to `django_login`.
   - *Rationale*: Eliminates any risk of `ValueError` regardless of entry point or session state.
3. **Streamlined Auth Handler Execution**:
   - *Decision*: In `TwoFactorVerifyView.post` and `TwoFactorSetupView.post`, invoke `_handle_successful_authentication_and_login(user, request)` to perform session creation, tracking, and cookie setup, followed by `otp_login(request, device)` to record OTP verification.
   - *Rationale*: Prevents duplicate `django_login(request, user)` calls and ensures consistent event tracking and session timeouts.

### Proposed Changes

#### 1. Auth Flow Interception (`openedx/core/djangoapps/user_authn/views/login.py`)
- In `login_user`:
  ```python
  if possibly_authenticated_user.is_staff and is_staff_2fa_enabled():
      request.session["pre_auth_staff_user_id"] = possibly_authenticated_user.id
      request.session["pre_auth_staff_backend"] = (
          getattr(possibly_authenticated_user, "backend", None) or settings.AUTHENTICATION_BACKENDS[0]
      )
      if redirect_url:
          request.session["pre_auth_staff_next_url"] = redirect_url
      # Return 2FA redirect
  ```
- In `_handle_successful_authentication_and_login(user, request)`:
  ```python
  if not getattr(user, "backend", None):
      user.backend = settings.AUTHENTICATION_BACKENDS[0]
  django_login(request, user)
  ```

#### 2. 2FA Views (`openedx/core/djangoapps/user_authn/views/two_factor.py`)
- Update `_get_staff_user(request)`:
  ```python
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
  ```
- In `TwoFactorVerifyView.post` and `TwoFactorSetupView.post`:
  - Pop `pre_auth_staff_backend` from session upon successful verification.
  - Call `_handle_successful_authentication_and_login(user, request)` followed by `otp_login(request, device)`.

### File Structure
- **Modified**:
  - `openedx/core/djangoapps/user_authn/views/login.py`
  - `openedx/core/djangoapps/user_authn/views/two_factor.py`
  - `openedx/core/djangoapps/user_authn/views/tests/test_two_factor.py`

# Testing

### Validation Approach
- Verify that both 2FA setup (`/account/2fa/setup/`) and 2FA verification (`/login/2fa/`) succeed seamlessly when multiple `AUTHENTICATION_BACKENDS` are configured in settings.
- Verify that pre-auth session attributes are cleanly cleared after successful device confirmation.

### Key Scenarios
- **2FA Device Enrollment with Multiple Backends**:
  - Configure `AUTHENTICATION_BACKENDS` with multiple backend classes (e.g. `ModelBackend`, `EmailAuthBackend`).
  - POST valid OTP confirmation code to `/account/2fa/setup/`.
  - Verify device confirmation, session establishment without `ValueError`, and successful redirection.
- **2FA Verification with Multiple Backends**:
  - POST valid OTP token to `/login/2fa/`.
  - Verify `django_login` succeeds and `user.is_authenticated` and `user.is_verified()` are both True.
- **Learner Non-Regression**:
  - Verify regular user logins complete normally without 2FA interception.

# Delivery Steps

### ✓ Step 1: Persist and restore authentication backend across 2FA flow
Fix the `ValueError` by preserving `user.backend` in pre-auth session and restoring it during 2FA setup/verification.

- Update `login_user` in `openedx/core/djangoapps/user_authn/views/login.py` to store `pre_auth_staff_backend`.
- Add backend fallback in `_handle_successful_authentication_and_login` in `login.py` to ensure `user.backend` is always defined before calling `django_login`.
- Update `_get_staff_user` in `openedx/core/djangoapps/user_authn/views/two_factor.py` to restore `user.backend` from session.
- Streamline `TwoFactorVerifyView.post` and `TwoFactorSetupView.post` to execute `_handle_successful_authentication_and_login` followed by `otp_login`, clearing `pre_auth_staff_backend`.

### ✓ Step 2: Add test coverage for multi-backend 2FA setup and verification
Add automated unit and regression tests verifying 2FA enrollment and verification under multiple authentication backends.

- Add test cases in `openedx/core/djangoapps/user_authn/views/tests/test_two_factor.py` with `@override_settings(AUTHENTICATION_BACKENDS=[...])` testing both `TwoFactorSetupView` and `TwoFactorVerifyView`.
- Verify clean session cleanup and non-regression of learner login flows.