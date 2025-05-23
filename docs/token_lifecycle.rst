Token Lifecycle Middleware
==========================

.. note::
   The Token Lifecycle system is an extension to the core functionality provided by the original
   `django-auth-adfs <https://github.com/snok/django-auth-adfs>`_ project. While building on the foundational
   authentication capabilities created by Joris Beckers and contributors, this feature adds specialized
   token management for Microsoft Entra ID and Graph API integration.

Traditionally, django-entra-auth is used **exclusively** as an authentication solution - it handles user authentication
via Microsoft Entra ID and maps claims to Django users. It doesn't really care about the access tokens after you've been authenticated.

The Token Lifecycle system extends django-entra-auth beyond pure authentication to also handle the complete lifecycle of access tokens
after the authentication process. This creates a more integrated approach where:

* The same application registration handles both authentication and resource access
* Tokens obtained during authentication are stored and refreshed automatically in the session
* The application can make delegated API calls on behalf of the user
* The system can optionally log out users when token refresh fails

How it works
------------

The token lifecycle system relies on the interplay between the ``TokenLifecycleMiddleware`` and the authentication backend:

1.  **Token Storage**: During authentication, if the ``TokenLifecycleMiddleware`` is enabled, the backend automatically stores and encrypts the access and refresh tokens in the user's session. If configured (``STORE_OBO_TOKEN=True``), it also attempts to acquire and store an OBO token.
2.  **Token Monitoring**: On each request for an authenticated user, the ``TokenLifecycleMiddleware`` triggers the backend to check the expiration status of the stored access token (and OBO token, if applicable).
3.  **Token Refresh**: If the backend determines a token is nearing expiration (based on ``TOKEN_REFRESH_THRESHOLD``), it uses the stored refresh token to attempt to acquire new tokens from Entra ID.
4.  **OBO Token Management**: The backend handles the acquisition and refresh of OBO tokens alongside the primary access/refresh tokens, if enabled.
5.  **Session Update**: If tokens are successfully refreshed, the backend updates the encrypted tokens stored in the session.
6.  **Security Controls**: The backend can be configured (``LOGOUT_ON_TOKEN_REFRESH_FAILURE=True``) to log out the user if token refresh fails. The middleware itself primarily initiates the checks.

Read more about the OBO flow: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow#protocol-diagram


.. warning::
    The Token Lifecycle system is a new feature in django-entra-auth and is considered experimental.
    Please be aware:

    **Currently no community support is guaranteed to be available for this feature**

    We recommend thoroughly testing this feature in your specific environment before deploying to production.

    Consider enabling the ``LOGOUT_ON_TOKEN_REFRESH_FAILURE`` setting,
    which allows you to log out users when token refresh fails.


Configuration
-------------

To enable the token lifecycle system, add the middleware to your ``MIDDLEWARE`` setting in your Django settings file:

.. code-block:: python

    MIDDLEWARE = [
        # ... other middleware
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django_entra_auth.middleware.TokenLifecycleMiddleware',  # Add this line
        # ... other middleware
    ]

.. important::
    The middleware must be placed after the ``SessionMiddleware`` and ``AuthenticationMiddleware``.


You can configure the token lifecycle behavior with these settings in your Django settings file:

.. code-block:: python

    ENTRA_AUTH = {
        # other settings

        # Number of seconds before expiration to refresh (default: 300, i.e., 5 minutes)
        "TOKEN_REFRESH_THRESHOLD": 300,

        # Enable or disable OBO token functionality (default: True)
        "STORE_OBO_TOKEN": True,

        # Custom salt for token encryption (optional)
        # If not specified, a default salt is used
        "TOKEN_ENCRYPTION_SALT": "your-custom-salt-string",

        # Automatically log out users when token refresh fails (default: False)
        "LOGOUT_ON_TOKEN_REFRESH_FAILURE": False,
    }

.. warning::
    If you change the ``TOKEN_ENCRYPTION_SALT`` after tokens have been stored in sessions, those tokens will no longer be decryptable.
    This effectively invalidates all existing tokens, requiring users to re-authenticate.

    Consider this when deploying changes to the salt in production environments.

Considerations
--------------

- Token storage and encryption are handled automatically by the backend during authentication when the ``TokenLifecycleMiddleware`` is enabled.
- Token refresh only works for authenticated users with valid sessions
- If the refresh token is invalid or expired, the system will not be able to refresh the access token
- By default, the system will not log the user out if token refresh fails, but this behavior can be changed with the ``LOGOUT_ON_TOKEN_REFRESH_FAILURE`` setting
- The system will not store tokens in the session when using the ``signed_cookies`` session backend
- OBO token storage is enabled by default but can be disabled with the ``STORE_OBO_TOKEN`` setting
- Using the OBO token versus the regular access token is dependent on the resources you are accessing and the permissions granted to your Entra ID application. See `the token types section <#understanding-access-tokens-vs-obo-tokens>`_ for more details.

**Token Refresh Failures**

By default, when token refresh fails, the system logs the error but allows the user to continue using the application until their session expires naturally. This behavior can be changed with the ``LOGOUT_ON_TOKEN_REFRESH_FAILURE`` setting:

- When set to ``False`` (default), users remain logged in even if their tokens can't be refreshed
- When set to ``True``, users are automatically logged out when token refresh fails

**Existing Sessions**

When deploying the Token Lifecycle system to an existing application with active user sessions, be aware of the following:

The system only captures tokens during the authentication process. Existing authenticated sessions won't have tokens stored in them, which means:

- Users with existing sessions won't have access to token-dependent features until they re-authenticate
- Utility functions like ``get_access_token()`` and ``get_obo_access_token()`` will return ``None`` for these sessions
- API calls that depend on these tokens will fail for existing sessions

The best approach is to ensure that all users re-authenticate after the system is deployed.

Azure AD Application Configuration
----------------------------------

When using the Token Lifecycle system, your Microsoft Entra ID application registration needs additional permissions
beyond those required for simple authentication. This extends the standard authentication-only setup with additional
API permissions needed for delegated access.

.. important::
    Your Django application's session cookie age must be set to a value that is less than that of your Entra ID application's refresh token lifetime.

    If a user's refresh token has expired, the user will be required to re-authenticate to continue making delegated requests.

Security Overview
-----------------------

**Token Encryption**

Tokens are automatically encrypted before being stored in the session and decrypted when they are retrieved.
The encryption is handled transparently by the TokenManager and utility functions.

**Signed Cookies Session Backend Restriction**

If you're using the ``signed_cookies`` session backend and need token storage, you won't be able to use the token lifecycle system.

.. note::
    This restriction only applies to the ``signed_cookies`` session backend. For other session backends (database, cache, file),
    tokens are stored securely on the server and only a session ID is stored in the cookie.

**Automatic OBO Token Acquisition**

By default, the system automatically requests OBO tokens when storing tokens. If your application doesn't need OBO tokens, you can disable this behavior to reduce unnecessary token requests (see `the OBO token configuration section <#disabling-obo-token-functionality>`_ for more details).

Disabling OBO Token Functionality
---------------------------------

By default, the Token Lifecycle system automatically requests and stores OBO (On-Behalf-Of) tokens.

If you don't need this functionality, you can disable it completely:

.. code-block:: python

    # In your Django settings.py
    ENTRA_AUTH = {
        "STORE_OBO_TOKEN": False,
    }

Note that disabling OBO tokens doesn't affect the regular access token functionality. Your application will still be able to use the access token obtained during authentication for its own resources and APIs that directly trust your application.

See `the token types section <#understanding-access-tokens-vs-obo-tokens>`_ for more details.

Accessing Tokens in Your Views
------------------------------

Since tokens are encrypted in the session, the TokenLifecycleMiddleware provides access to the authentication backend instance as ``request.token_storage``, which helps you access tokens safely:

.. code-block:: python

    # For your own APIs or APIs that trust your application directly
    access_token = request.token_storage.get_access_token(request)

    # For Microsoft Graph API or other APIs requiring delegated access
    obo_token = request.token_storage.get_session_obo_access_token(request)

The backend automatically handles encryption/decryption of tokens, so you don't need to worry about the encryption details.

.. warning::
    You should always use the ``request.token_storage`` methods to access tokens rather than accessing them directly from the session.
    Direct access to the raw token data stored in the session will give you the encrypted token, not the actual token value.

Examples
----------------------

Here are practical examples of using the token storage in your views:

Using with Microsoft Graph API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example demonstrates using the OBO token to access Microsoft Graph API

.. code-block:: python

    from django.contrib.auth.decorators import login_required
    from django.http import JsonResponse
    import requests

    @login_required
    def me_view(request):
        """Get the user's profile from Microsoft Graph API"""
        obo_token = request.token_storage.get_session_obo_access_token(request)

        if not obo_token:
            return JsonResponse({"error": "No OBO token available"}, status=401)

        headers = {
            "Authorization": f"Bearer {obo_token}",
            "Content-Type": "application/json",
        }

        try:
            response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
            response.raise_for_status()
            return JsonResponse(response.json())
        except requests.exceptions.RequestException as e:
            return JsonResponse(
                {"error": "Failed to fetch user profile", "details": str(e)},
                status=500
            )

Using with Custom Entra ID-Protected API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example shows how to use the OBO token to access a custom API protected by Entra ID that supports the OBO flow.

.. code-block:: python

    from django.contrib.auth.decorators import login_required
    from django.http import JsonResponse
    import requests

    @login_required
    def custom_api_view(request):
        """Access a custom API using OBO token"""
        obo_token = request.token_storage.get_session_obo_access_token(request)

        if not obo_token:
            return JsonResponse({"error": "No OBO token available"}, status=401)

        headers = {
            "Authorization": f"Bearer {obo_token}",
            "Content-Type": "application/json",
        }

        try:
            response = requests.get(
                "https://your-custom-api.example.com/data",
                headers=headers
            )
            response.raise_for_status()
            return JsonResponse(response.json())
        except requests.exceptions.RequestException as e:
            return JsonResponse(
                {"error": "Failed to fetch data", "details": str(e)},
                status=500
            )

Using with Direct Resource Access
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For APIs that directly trust your application (no OBO flow needed), use the regular access token:

.. code-block:: python

    from rest_framework.views import APIView
    from rest_framework.response import Response
    import requests

    class ExternalApiView(APIView):
        def get(self, request):
            """Call an API that accepts your application's token"""
            token = request.token_storage.get_access_token(request)

            if not token:
                return Response({"error": "No access token available"}, status=401)

            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get("https://api.example.com/data", headers=headers)

            return Response(response.json())

Debug view
----------

The following example code demonstrates a debug view to check the values of the tokens stored in the session:

.. code-block:: python

    import requests
    from django.contrib.auth.decorators import login_required
    from django.http import JsonResponse
    from datetime import datetime
    from django_entra_auth.backend import AdfsBaseBackend

    @login_required
    def debug_view(request):
        """
        Debug view that provides detailed information about the authentication state,
        tokens, and session data.
        """
        if not request.user.is_authenticated:
            return JsonResponse({"authenticated": False})

        backend = request.token_storage if hasattr(request, "token_storage") else AdfsBaseBackend()

        # Basic session token info
        session_info = {
            "has_access_token": backend.ACCESS_TOKEN_KEY in request.session,
            "has_refresh_token": backend.REFRESH_TOKEN_KEY in request.session,
            "has_expires_at": backend.TOKEN_EXPIRES_AT_KEY in request.session,
        }

        # Add token expiration details if available
        if backend.TOKEN_EXPIRES_AT_KEY in request.session:
            try:
                expires_at = datetime.fromisoformat(
                    request.session[backend.TOKEN_EXPIRES_AT_KEY]
                )
                now = datetime.now()
                session_info["token_expires_at"] = expires_at.isoformat()
                session_info["expires_in_seconds"] = max(
                    0, int((expires_at - now).total_seconds())
                )
                session_info["is_expired"] = expires_at <= now
            except (ValueError, TypeError) as e:
                session_info["expiration_parse_error"] = str(e)

        # Show raw encrypted tokens for debugging
        if backend.ACCESS_TOKEN_KEY in request.session:
            raw_token = request.session[backend.ACCESS_TOKEN_KEY]
            session_info["raw_token_preview"] = f"{raw_token[:10]}...{raw_token[-10:]}"
            session_info["raw_token_length"] = len(raw_token)

            # Try to decode as JWT without decryption (should fail if properly encrypted)
            try:
                import jwt
                jwt.decode(raw_token, options={"verify_signature": False})
                session_info["is_encrypted"] = False
            except:
                session_info["is_encrypted"] = True

        # Get properly decrypted access token
        try:
            access_token = backend.get_access_token(request)
            session_info["decrypted_access_token_available"] = access_token is not None

            if access_token:
                if len(access_token) > 20:
                    session_info["decrypted_access_token_preview"] = (
                        f"{access_token[:10]}...{access_token[-10:]}"
                    )
                session_info["decrypted_access_token_length"] = len(access_token)

                # Try to decode as JWT (should succeed if properly decrypted)
                try:
                    import jwt
                    decoded = jwt.decode(access_token, options={"verify_signature": False})
                    session_info["jwt_decode_success"] = True
                    # Add some basic JWT info without exposing sensitive data
                    if "exp" in decoded:
                        exp_time = datetime.fromtimestamp(decoded["exp"])
                        session_info["jwt_expiry"] = exp_time.isoformat()
                except Exception as e:
                    session_info["jwt_decode_error"] = str(e)
        except Exception as e:
            session_info["access_token_error"] = f"Error getting access token: {str(e)}"

        # Check if OBO token is available
        try:
            obo_token = backend.get_session_obo_access_token(request)
            obo_info = {
                "has_obo_token": obo_token is not None,
            }

            # Show raw encrypted OBO token if available
            if backend.OBO_ACCESS_TOKEN_KEY in request.session:
                raw_obo = request.session[backend.OBO_ACCESS_TOKEN_KEY]
                obo_info["raw_obo_preview"] = f"{raw_obo[:10]}...{raw_obo[-10:]}"
                obo_info["raw_obo_length"] = len(raw_obo)

            if obo_token:
                if len(obo_token) > 20:
                    obo_info["obo_token_preview"] = f"{obo_token[:10]}...{obo_token[-10:]}"
                obo_info["obo_token_length"] = len(obo_token)

                # Try to decode as JWT (should succeed if properly decrypted)
                try:
                    import jwt
                    decoded = jwt.decode(obo_token, options={"verify_signature": False})
                    obo_info["jwt_decode_success"] = True
                    # Add some basic JWT info without exposing sensitive data
                    if "exp" in decoded:
                        exp_time = datetime.fromtimestamp(decoded["exp"])
                        obo_info["jwt_expiry"] = exp_time.isoformat()
                except Exception as e:
                    obo_info["jwt_decode_error"] = str(e)
        except Exception as e:
            obo_info = {"error": f"Error getting OBO token: {str(e)}"}

        # Return all the collected information
        return JsonResponse(
            {
                "authenticated": True,
                "user": {
                    "id": request.user.id,
                    "username": request.user.username,
                    "email": request.user.email,
                    "is_staff": request.user.is_staff,
                    "is_superuser": request.user.is_superuser,
                },
                "session_tokens": session_info,
                "obo_token": obo_info,
            },
            json_dumps_params={"indent": 2},
        )

Understanding Access Tokens vs. OBO Tokens
------------------------------------------

For more information on the different types of permissions and flows, see:

* `OAuth 2.0 On-Behalf-Of flow <https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow>`_
* `Permission types <https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview>`_
