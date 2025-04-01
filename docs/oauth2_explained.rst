OpenID Connect with Microsoft Entra ID
===================================

This chapter explains how Microsoft Entra ID implements OpenID Connect and how we use it in Django.

OpenID Connect Overview
-------------------------

`OpenID Connect <https://openid.net/specs/openid-connect-core-1_0.html>`__ is an identity layer built on top of OAuth 2.0.
It enables applications to verify user identities and obtain basic profile information in a standardized way.

    OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 [RFC6749]
    protocol. It enables Clients to verify the identity of the End-User based on the
    authentication performed by an Authorization Server, as well as to obtain basic
    profile information about the End-User in an interoperable and REST-like manner.

The access token returned by OpenID Connect is a signed JWT token (JSON Web Token) containing claims about the user.
``django-entra-auth`` uses this access token to:
- Validate the token issuer by verifying the signature
- Keep the Django users database up to date
- Authenticate users based on the claims in the token

Microsoft Entra ID and OpenID Connect
--------------------------------

Microsoft Entra ID fully supports the OpenID Connect protocol, providing a robust identity and access management solution.
``django-entra-auth`` uses the Authorization Code Flow, which is the most secure flow for server-side applications.

Authentication Flow in Django
-----------------

Let's step through how ``django-entra-auth`` uses OpenID Connect to authenticate and authorize users.

.. code-block::
    text

     +----------+
     |          |
     |   User   |
     |          |
     +----------+
          ^
          |
         (B)
     +----|-----+          Client Identifier    +---------------+
     |         -+----(A)-- & Redirect URI ---->|               |
     | Web      |                              |  Entra ID     |
     | Browser -+----(B)-- Authenticates ----->|   Server      |
     |          |                              |               |
     |         -+----(C)-- Auth Code --------<|               |
     +-|---|----+                              +---------------+
       |   |  ^                                    ^      v
      (A) (C)(G)                                   |      |
       |   |  |                                    |      |
       ^   v  |                                    |      |
     +--------|+                                   |      |
     |         |>---(D)-- Auth Code ---------------|      |
     |  Django |         & Redirect URI            |      |
     |  Login  |                                   |      |
     |         |<---(E)---- ID Token -------------|      |
     +---------+         Access Token              |      |
       |    ^            Refresh Token             |      |
       |    |                                      |      |
      (F) Access Token                             |      |
       |   (G) Session ID                          |      |
       v    |                                      |      |
     +-------------------------------+             |      |
     |                               |             |      |
     | Django Authentication Backend |             |      |
     |                               |             |      |
     +-------------------------------+             |      |

The flow works as follows:

1. The user clicks login and is redirected to Entra ID
2. User authenticates with Entra ID (if not already authenticated)
3. Entra ID sends an authorization code back to Django
4. Django exchanges the code for tokens
5. The authentication backend validates the tokens and creates/updates the user
6. A session is created and the user is logged in

Once authenticated, Django uses its standard session mechanism for subsequent requests.

Token Types
----------

The OpenID Connect flow provides several types of tokens:

- **ID Token**: Contains claims about the user's identity
- **Access Token**: Used for accessing protected resources
- **Refresh Token**: Used to obtain new access tokens

``django-entra-auth`` primarily uses the ID token for authentication and user information.
The access and refresh tokens are used by the TokenLifecycleMiddleware for maintaining
access to Microsoft Graph API and other protected resources.

For more information on tokens and permissions in Microsoft Entra ID, see:

* `OpenID Connect on Microsoft Entra ID <https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc>`_
* `Permission types <https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview>`_
