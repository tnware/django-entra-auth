Credits
=======

django-entra-auth is built upon the excellent work of Joris Beckers and contributors to the
`django-auth-adfs <https://github.com/snok/django-auth-adfs>`_ project.

Original Project
---------------

* **Project**: `django-auth-adfs <https://github.com/snok/django-auth-adfs>`_
* **License**: BSD License
* **Original Author**: Joris Beckers
* **Maintainer**: `Snok <https://github.com/snok>`_

The original django-auth-adfs project provided authentication for both ADFS on Windows Server and
Azure AD. Our project focuses specifically on Microsoft Entra ID (formerly Azure AD) with additional
features like token lifecycle management and simplified Microsoft Graph API access.

We maintain the same BSD license as the original project and have structured our codebase to be
familiar to users of django-auth-adfs where possible.

Acknowledgments
--------------

We would like to express our sincere gratitude to:

* Joris Beckers for creating the original django-auth-adfs project
* All contributors to django-auth-adfs who helped build and improve the foundation
* The Django community for their commitment to creating and maintaining high-quality open source software

Areas of Derivation
------------------

The following areas of our project are derived from django-auth-adfs:

* Core authentication backend structure
* Claims mapping and group synchronization
* Basic middleware functionality
* OAuth2/OpenID Connect implementation

We've extended the original work with:

* Microsoft Entra ID specific optimizations
* Token lifecycle management system