Frequently Asked Questions
==========================

Why am I always redirected to ``/accounts/profile/`` after login?
-----------------------------------------------------------------
This is default Django behaviour. You can change it by setting the Django setting named
`LOGIN_REDIRECT_URL <https://docs.djangoproject.com/en/dev/ref/settings/#login-redirect-url>`_.

How do I store additional info about a user?
--------------------------------------------
``django_entra_auth`` can only store information in existing fields of the user model.
If you want to store extra info, you'll have to extend the default user model with extra fields and adjust
the :ref:`claim_mapping_setting` setting accordingly.

`You can read about how to extend the user model here <https://simpleisbetterthancomplex.com/tutorial/2016/07/22/how-to-extend-django-user-model.html#abstractuser>`_

I'm receiving a ``KeyError: 'upn'`` error when authenticating.
--------------------------------------------------------------------------------
In some circumstances, Entra ID does not send the ``upn`` claim used to determine the username. This is observed to happen
with guest users who's **source** in the users overview of Entra ID is ``Microsoft Account`` instead of
``Microsoft Entra ID``.

In such cases, try setting the :ref:`username_claim_setting` to ``email`` instead of the default ``upn``. Or create a
new user in your Entra ID directory.

Why is a user added and removed from the same group on every login?
-------------------------------------------------------------------
This can be caused by having a case insensitive database, such as a ``MySQL`` database with default settings.
You can read more about `collation settings <https://docs.djangoproject.com/en/3.0/ref/databases/#collation-settings>`_
in the official documentation.

The redirect_uri starts with HTTP, while my site is HTTPS only.
---------------------------------------------------------------
When you run Django behind a TLS terminating webserver or load balancer, then Django doesn't know the client arrived
over a HTTPS connection. It will only see the plain HTTP traffic. Therefore, the link it generates and sends to Entra ID
as the ``redirect_uri`` query parameter, will start with HTTP, instead of HTTPS.

To tell Django to generate HTTPS links, you need to set its ``SECURE_PROXY_SSL_HEADER`` setting and inject the correct
HTTP header and value on your web server.

For more info, have a look at `Django's docs <https://docs.djangoproject.com/en/dev/ref/settings/#secure-proxy-ssl-header>`_.

I cannot get it working!
------------------------
Make sure you follow the instructions in the troubleshooting guide.
It will enable debugging and can quickly tell you what is wrong.

Also, walk through the :ref:`settings` once, you might find one
that needs to be adjusted to match your situation.

What is the relationship between django-entra-auth and django-auth-adfs?
-----------------------------------------------------------------------
django-entra-auth is derived from the work of Joris Beckers and contributors on
`django-auth-adfs <https://github.com/snok/django-auth-adfs>`_. The original project provided
authentication for both ADFS on Windows Server and Azure AD.

This project focuses specifically on Microsoft Entra ID (formerly Azure AD) integration, with
specialized features like the token lifecycle management system and On-Behalf-Of token support
for Microsoft Graph API access. We have maintained compatibility with the original API where
possible, which is why many class names still have the "Adfs" prefix.

We're grateful to the original authors for their excellent work which made this specialized
version possible.
