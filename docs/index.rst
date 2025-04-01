Microsoft Entra ID Authentication for Django
=====================================

.. image:: https://img.shields.io/pypi/v/django-entra-auth.svg
    :target: https://pypi.python.org/pypi/django-entra-auth
.. image:: https://img.shields.io/pypi/pyversions/django-entra-auth.svg
    :target: https://pypi.python.org/pypi/django-entra-auth#downloads
.. image:: https://img.shields.io/pypi/djversions/django-entra-auth.svg
    :target: https://pypi.python.org/pypi/django-entra-auth

A Django authentication backend for Microsoft Entra ID (formerly Azure AD)

* Free software: BSD License
* Homepage: https://github.com/tnware/django-entra-auth
* Documentation: http://django-entra-auth.readthedocs.io/

.. important::
   This project is derived from the excellent work by Joris Beckers and contributors on
   `django-auth-adfs <https://github.com/snok/django-auth-adfs>`_. We maintain the same
   BSD license and have adapted their codebase for Microsoft Entra ID-specific functionality.
   Many thanks to the original authors for their contributions to the Django authentication ecosystem.

Features
--------

* Integrates Django with Microsoft Entra ID in the cloud
* Provides seamless single sign on (SSO) for your Django project
* Auto creates users and adds them to Django groups based on info received from Entra ID
* Django Rest Framework (DRF) integration: Authenticate against your API with an Entra ID access token

.. note::
   While this library fully supports Microsoft Entra ID (formerly Azure AD), you'll notice that many class names
   in the code still use "Adfs" prefix (e.g., ``AdfsBaseBackend``, ``AdfsAuthCodeBackend``). This naming is
   historical and maintained for backward compatibility. The library works with Microsoft Entra ID regardless of
   these class names.

Contents
--------

.. toctree::
    :maxdepth: 3

    install
    oauth2_explained
    settings_ref
    config_guides
    middleware
    token_lifecycle
    signals
    rest_framework
    demo
    troubleshooting
    faq
    contributing
    credits
