"""
Tests for the TokenLifecycleMiddleware.
"""

import datetime
import json
import base64
from unittest.mock import Mock, patch
import time

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import TestCase, RequestFactory, override_settings
from django.contrib.sessions.backends.db import SessionStore

from django_entra_auth.middleware import TokenLifecycleMiddleware
from django_entra_auth.config import settings as adfs_settings
from django_entra_auth.backend import AdfsBaseBackend
from tests.settings import MIDDLEWARE

User = get_user_model()

MIDDLEWARE_WITH_TOKEN_LIFECYCLE = MIDDLEWARE + (
    "django_entra_auth.middleware.TokenLifecycleMiddleware",
)


def create_test_token(claims=None, exp_delta=3600):
    """Create a test JWT token with the given claims and expiration delta."""
    if claims is None:
        claims = {}

    # Create a basic JWT token with Entra ID-like structure
    header = {"typ": "JWT", "alg": "RS256", "x5t": "example-thumbprint"}

    # Add standard ADFS claims if not present
    now = int(time.time())
    if "iat" not in claims:
        claims["iat"] = now
    if "exp" not in claims:
        claims["exp"] = now + exp_delta
    if "aud" not in claims:
        claims["aud"] = "microsoft:identityserver:your-RelyingPartyTrust-identifier"
    if "iss" not in claims:
        claims["iss"] = "https://sts.windows.net/01234567-89ab-cdef-0123-456789abcdef/"
    if "sub" not in claims:
        claims["sub"] = "john.doe@example.com"

    # Encode each part
    header_part = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    )
    claims_part = (
        base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    )
    signature_part = base64.urlsafe_b64encode(b"test_signature").rstrip(b"=").decode()

    # Combine parts
    return f"{header_part}.{claims_part}.{signature_part}"


@override_settings(MIDDLEWARE=MIDDLEWARE_WITH_TOKEN_LIFECYCLE)
class TokenLifecycleTests(TestCase):
    """
    Tests for the token lifecycle functionality in TokenLifecycleMiddleware.
    """

    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username="testuser")
        self.request = self.factory.get("/")
        self.request.user = self.user
        self.request.session = SessionStore()
        self.middleware = TokenLifecycleMiddleware(lambda r: None)
        self.backend = AdfsBaseBackend()

        # Set up default provider config mock
        patcher = patch("django_entra_auth.backend.provider_config")
        self.mock_provider = patcher.start()
        self.mock_provider.token_endpoint = (
            "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token"
        )

        # Set up default mock responses
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "token_type": "Bearer",
            "scope": "https://graph.microsoft.com/.default",
            "expires_in": 3600,
            "access_token": create_test_token({"type": "obo"}),
        }
        self.mock_provider.session.post.return_value = mock_response
        self.mock_provider.session.get.return_value = mock_response
        self.addCleanup(patcher.stop)

    def test_settings_configuration(self):
        """Test settings are properly loaded from Django settings"""
        original_threshold = adfs_settings.TOKEN_REFRESH_THRESHOLD
        original_store_obo = adfs_settings.STORE_OBO_TOKEN
        original_logout = adfs_settings.LOGOUT_ON_TOKEN_REFRESH_FAILURE

        try:
            # Set test values
            adfs_settings.TOKEN_REFRESH_THRESHOLD = 600
            adfs_settings.STORE_OBO_TOKEN = False
            adfs_settings.LOGOUT_ON_TOKEN_REFRESH_FAILURE = True

            # Create a new backend instance to pick up the new settings
            backend = AdfsBaseBackend()
            self.assertEqual(backend.refresh_threshold, 600)
            self.assertFalse(backend.store_obo_token)
            self.assertTrue(backend.logout_on_refresh_failure)
        finally:
            # Restore original values
            adfs_settings.TOKEN_REFRESH_THRESHOLD = original_threshold
            adfs_settings.STORE_OBO_TOKEN = original_store_obo
            adfs_settings.LOGOUT_ON_TOKEN_REFRESH_FAILURE = original_logout

    def test_token_storage_capability(self):
        """Test token storage capability is properly added by middleware"""
        # Test with no session
        request_without_session = self.factory.get("/")
        self.middleware(request_without_session)
        self.assertFalse(hasattr(request_without_session, "token_storage"))

        # Test with signed cookies
        with patch.object(self.middleware.backend, "using_signed_cookies", True):
            self.middleware(self.request)
            self.assertFalse(hasattr(self.request, "token_storage"))

        # Test with valid session
        with patch.object(self.middleware.backend, "using_signed_cookies", False):
            self.middleware(self.request)
            self.assertTrue(hasattr(self.request, "token_storage"))
            self.assertIs(self.request.token_storage, self.middleware.backend)

    def test_token_storage_and_retrieval(self):
        """Test the complete token storage and retrieval flow"""
        access_token = create_test_token({"type": "access"})
        refresh_token = create_test_token({"type": "refresh"})

        # Add token storage capability
        self.middleware(self.request)

        # Store tokens
        self.request.token_storage.store_tokens(
            self.request,
            access_token,
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": 3600,
            },
        )

        # Verify storage
        self.assertEqual(self.backend.get_access_token(self.request), access_token)
        self.assertTrue(self.backend.TOKEN_EXPIRES_AT_KEY in self.request.session)

        # Verify encryption
        encrypted = self.request.session[self.backend.ACCESS_TOKEN_KEY]
        self.assertNotEqual(encrypted, access_token)
        self.assertEqual(self.backend.decrypt_token(encrypted), access_token)

    def test_token_refresh_flow(self):
        """Test the complete token refresh flow"""
        old_access_token = create_test_token({"type": "access"}, exp_delta=60)
        old_refresh_token = create_test_token({"type": "refresh"})
        new_access_token = create_test_token({"type": "access"})
        new_refresh_token = create_test_token({"type": "refresh"})

        # Add token storage capability and setup expired token
        self.middleware(self.request)
        self.request.token_storage.store_tokens(
            self.request,
            old_access_token,
            {
                "access_token": old_access_token,
                "refresh_token": old_refresh_token,
                "expires_in": 60,  # Will trigger refresh
            },
        )

        # Mock refresh response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "expires_in": 3600,
        }
        self.mock_provider.session.post.return_value = mock_response

        # Trigger refresh via middleware
        self.middleware(self.request)

        # Verify tokens were updated
        self.assertEqual(self.backend.get_access_token(self.request), new_access_token)

    def test_obo_token_management(self):
        """Test OBO token functionality when enabled"""
        access_token = create_test_token({"type": "access"})
        obo_token = create_test_token({"type": "obo"})

        # Add token storage capability and store regular token
        self.middleware(self.request)
        self.request.token_storage.store_tokens(
            self.request,
            access_token,
            {"access_token": access_token, "expires_in": 3600},
        )

        # Mock successful token response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": obo_token,
            "expires_in": 3600,
        }
        self.mock_provider.session.post.return_value = mock_response
        self.mock_provider.session.get.return_value = mock_response

        # Mock token validation
        with patch.object(self.backend, "validate_access_token") as mock_validate:
            mock_validate.return_value = {"sub": "test_user", "groups": ["group1"]}

            # Store OBO token for testing
            self.request.session[self.backend.OBO_ACCESS_TOKEN_KEY] = (
                self.backend.encrypt_token(obo_token)
            )
            self.request.session[self.backend.OBO_TOKEN_EXPIRES_AT_KEY] = (
                datetime.datetime.now() + datetime.timedelta(hours=1)
            ).isoformat()

            # Test retrieval
            stored_token = self.backend.get_session_obo_access_token(self.request)
            self.assertEqual(stored_token, obo_token)

    def test_error_handling(self):
        """Test error handling in various scenarios"""
        # Add token storage capability
        self.middleware(self.request)

        # Test invalid data handling
        self.assertIsNone(self.backend.decrypt_token("invalid_data"))
        self.assertIsNone(self.backend.encrypt_token(None))

        # Test refresh failure
        access_token = create_test_token({"type": "access"}, exp_delta=-60)
        refresh_token = create_test_token({"type": "refresh"})

        with patch("django_entra_auth.backend.provider_config") as mock_config:
            mock_config.token_endpoint = (
                "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token"
            )

            # Setup expired tokens first
            self.request.token_storage.store_tokens(
                self.request,
                access_token,
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_in": -60,  # Already expired
                },
            )

            # Mock a 400 error response with proper JSON error format
            error_response = Mock(status_code=400)
            error_response.json.return_value = {
                "error": "invalid_grant",
                "error_description": "Token refresh failed",
            }
            error_response.text = "Token refresh failed"
            mock_config.session.post.return_value = error_response

            self.backend.logout_on_refresh_failure = True
            try:
                with patch("django_entra_auth.backend.logout") as mock_logout:
                    self.backend.refresh_tokens(self.request)
                    mock_logout.assert_called_once_with(self.request)
            finally:
                self.backend.logout_on_refresh_failure = False

    def test_signed_cookies_handling(self):
        """Test behavior with signed cookies session backend"""
        with patch.object(self.middleware.backend, "using_signed_cookies", True):
            self.middleware(self.request)
            self.assertFalse(hasattr(self.request, "token_storage"))

    def test_middleware_integration(self):
        """Test TokenLifecycleMiddleware integration"""
        # Test with unauthenticated user
        request = self.factory.get("/")
        request.user = AnonymousUser()
        request.session = SessionStore()
        self.middleware(request)
        self.assertTrue(hasattr(request, "token_storage"))

    def test_clear_tokens(self):
        """Test clearing tokens from session"""
        access_token = create_test_token({"type": "access"})
        refresh_token = create_test_token({"type": "refresh"})

        # Add token storage capability and store tokens
        self.middleware(self.request)
        self.request.token_storage.store_tokens(
            self.request,
            access_token,
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": 3600,
            },
        )

        # Verify tokens were stored
        self.assertTrue(self.backend.ACCESS_TOKEN_KEY in self.request.session)
        self.assertTrue(self.backend.REFRESH_TOKEN_KEY in self.request.session)

        # Clear tokens
        success = self.backend.clear_tokens(self.request)
        self.assertTrue(success)

        # Verify tokens were cleared
        self.assertFalse(self.backend.ACCESS_TOKEN_KEY in self.request.session)
        self.assertFalse(self.backend.REFRESH_TOKEN_KEY in self.request.session)
        self.assertFalse(self.backend.TOKEN_EXPIRES_AT_KEY in self.request.session)
        self.assertFalse(self.backend.OBO_ACCESS_TOKEN_KEY in self.request.session)
        self.assertFalse(self.backend.OBO_TOKEN_EXPIRES_AT_KEY in self.request.session)

    def test_refresh_obo_token_directly(self):
        """Test direct OBO token refresh"""
        access_token = create_test_token({"type": "access"})
        new_obo_token = create_test_token({"type": "obo"})

        # Add token storage capability and store access token
        self.middleware(self.request)
        self.request.token_storage.store_tokens(
            self.request,
            access_token,
            {"access_token": access_token, "expires_in": 3600},
        )

        # Mock successful token response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": new_obo_token,
            "expires_in": 3600,
        }
        self.mock_provider.session.post.return_value = mock_response
        self.mock_provider.session.get.return_value = mock_response

        # Mock token validation
        with patch.object(self.backend, "validate_access_token") as mock_validate:
            mock_validate.return_value = {"sub": "test_user", "groups": ["group1"]}

            # Refresh OBO token
            success = self.backend.refresh_obo_token(self.request)
            self.assertTrue(success)

            # Verify new OBO token was stored
            stored_token = self.backend.get_session_obo_access_token(self.request)
            self.assertEqual(stored_token, new_obo_token)
            self.assertTrue(
                self.backend.OBO_TOKEN_EXPIRES_AT_KEY in self.request.session
            )
