Middleware
==========

django-entra-auth provides two middleware components that offer different functionality:

1. ``LoginRequiredMiddleware`` - Forces login for all views
2. ``TokenLifecycleMiddleware`` - Manages access token lifecycle (refreshing, encryption, etc.)

Login Required Middleware
-------------------------

**django-entra-auth** ships with a middleware class named ``LoginRequiredMiddleware``.
You can use it to force an unauthenticated user to login and be redirected to the URL specified in in Django's
``LOGIN_URL`` setting without having to add code to every view.

By default it's disabled for the page defined in the ``LOGIN_URL`` setting and the redirect page for Entra ID.
But by setting the ``LOGIN_EXEMPT_URLS`` setting, you can exclude other pages from authentication.
Have a look at the :ref:`settings` for more information.

To enable the middleware, add it to ``MIDDLEWARE`` in ``settings.py`` (or ``MIDDLEWARE_CLASSES`` if using Django <1.10).
Make sure to add it after any other session or authentication middleware to be sure all other methods of identifying
the user are tried first.

In your ``settings.py`` file, add the following:

.. code-block:: python

    MIDDLEWARE = (
        ...
        'django_entra_auth.middleware.LoginRequiredMiddleware',
    )

    ENTRA_AUTH = {
        ...
        "LOGIN_EXEMPT_URLS": ["api/", "public/"],
        ...
    }

Token Lifecycle Middleware
--------------------------

The ``TokenLifecycleMiddleware`` extends django-entra-auth beyond authentication to also manage the complete lifecycle
of access tokens. It enables:

* Storing and encrypting tokens in the user's session
* Automatically refreshing tokens before they expire
* Accessing Microsoft Graph API with OBO tokens
* Optionally logging out users when token refresh fails

Basic configuration:

.. code-block:: python

    MIDDLEWARE = [
        # ... other middleware
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django_entra_auth.middleware.TokenLifecycleMiddleware',  # Add this line
        # ... other middleware
    ]

    ENTRA_AUTH = {
        # other settings
        "TOKEN_REFRESH_THRESHOLD": 300,  # refresh 5 minutes before expiry
        "STORE_OBO_TOKEN": True,         # enable OBO token storage
        "LOGOUT_ON_TOKEN_REFRESH_FAILURE": False,  # don't log out on refresh failure
    }

.. note::
   For complete documentation on the Token Lifecycle system, including detailed configuration options,
   security considerations, and usage examples, see the :doc:`token_lifecycle` section.
