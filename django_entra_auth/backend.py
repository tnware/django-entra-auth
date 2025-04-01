import logging
import datetime
import base64

import jwt
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group
from django.core.exceptions import (
    ImproperlyConfigured,
    ObjectDoesNotExist,
    PermissionDenied,
)
from django.contrib.auth import logout

from django_entra_auth import signals
from django_entra_auth.config import provider_config, settings
from django_entra_auth.exceptions import MFARequired
from django.conf import settings as django_settings
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger("django_entra_auth")


class AdfsBaseBackend(ModelBackend):
    # Session key constants
    ACCESS_TOKEN_KEY = "ADFS_ACCESS_TOKEN"
    REFRESH_TOKEN_KEY = "ADFS_REFRESH_TOKEN"
    TOKEN_EXPIRES_AT_KEY = "ADFS_TOKEN_EXPIRES_AT"
    OBO_ACCESS_TOKEN_KEY = "ADFS_OBO_ACCESS_TOKEN"
    OBO_TOKEN_EXPIRES_AT_KEY = "ADFS_OBO_TOKEN_EXPIRES_AT"

    def __init__(self):
        super().__init__()
        # Token management settings
        self.refresh_threshold = getattr(settings, "TOKEN_REFRESH_THRESHOLD", 300)
        self.store_obo_token = getattr(settings, "STORE_OBO_TOKEN", True)
        self.logout_on_refresh_failure = getattr(
            settings, "LOGOUT_ON_TOKEN_REFRESH_FAILURE", False
        )
        self.using_signed_cookies = (
            django_settings.SESSION_ENGINE
            == "django.contrib.sessions.backends.signed_cookies"
        )

        if self.using_signed_cookies:
            logger.warning(
                "AdfsBaseBackend: Storing tokens in signed cookies is not recommended for security "
                "reasons and cookie size limitations. Token storage will be disabled."
            )

    def _get_encryption_key(self):
        """
        Derive a Fernet encryption key from Django's SECRET_KEY.

        Returns:
            bytes: A 32-byte key suitable for Fernet encryption
        """
        default_salt = b"django_entra_auth_token_encryption"
        salt = getattr(settings, "TOKEN_ENCRYPTION_SALT", default_salt)

        if isinstance(salt, str):
            salt = salt.encode()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(django_settings.SECRET_KEY.encode()))
        return key

    def encrypt_token(self, token):
        """
        Encrypt a token using Django's SECRET_KEY.

        Args:
            token (str): The token to encrypt

        Returns:
            str: The encrypted token as a string or None if encryption fails
        """
        if not token:
            return None

        try:
            key = self._get_encryption_key()
            f = Fernet(key)
            encrypted_token = f.encrypt(token.encode())
            return encrypted_token.decode()
        except Exception as e:
            logger.error(f"Error encrypting token: {e}")
            return None

    def decrypt_token(self, encrypted_token):
        """
        Decrypt a token that was encrypted using Django's SECRET_KEY.

        Args:
            encrypted_token (str): The encrypted token

        Returns:
            str: The decrypted token or None if decryption fails
        """
        if not encrypted_token:
            return None

        try:
            key = self._get_encryption_key()
            f = Fernet(key)
            decrypted_token = f.decrypt(encrypted_token.encode())
            return decrypted_token.decode()
        except Exception as e:
            logger.error(f"Error decrypting token: {e}")
            return None

    def store_tokens(self, request, access_token, adfs_response=None):
        """
        Store tokens in the session, encrypting them first.

        Args:
            request: The current request object
            access_token (str): The access token to store
            adfs_response (dict): Optional response from ADFS containing refresh token and expiry

        Returns:
            bool: True if tokens were stored, False otherwise
        """
        if not hasattr(request, "session"):
            return False

        try:
            session_modified = False

            encrypted_token = self.encrypt_token(access_token)
            if encrypted_token:
                request.session[self.ACCESS_TOKEN_KEY] = encrypted_token
                session_modified = True
                logger.debug("Stored access token")

            if adfs_response and "refresh_token" in adfs_response:
                refresh_token = adfs_response["refresh_token"]
                if refresh_token:
                    encrypted_token = self.encrypt_token(refresh_token)
                    if encrypted_token:
                        request.session[self.REFRESH_TOKEN_KEY] = encrypted_token
                        session_modified = True
                        logger.debug("Stored refresh token")
                    else:
                        logger.warning("Failed to encrypt refresh token")
                else:
                    logger.warning("Empty refresh token received from ADFS")
            else:
                logger.debug("No refresh token in ADFS response")

            if adfs_response and "expires_in" in adfs_response:
                expires_at = datetime.datetime.now() + datetime.timedelta(
                    seconds=int(adfs_response["expires_in"])
                )
                request.session[self.TOKEN_EXPIRES_AT_KEY] = expires_at.isoformat()
                session_modified = True
                logger.debug("Stored token expiration")

            if self.store_obo_token:
                try:
                    obo_token = self.get_obo_access_token(access_token)
                    if obo_token:
                        encrypted_token = self.encrypt_token(obo_token)
                        if encrypted_token:
                            request.session[self.OBO_ACCESS_TOKEN_KEY] = encrypted_token
                            import jwt

                            decoded_token = jwt.decode(
                                obo_token, options={"verify_signature": False}
                            )
                            if "exp" in decoded_token:
                                obo_expires_at = datetime.datetime.fromtimestamp(
                                    decoded_token["exp"]
                                )
                                request.session[self.OBO_TOKEN_EXPIRES_AT_KEY] = (
                                    obo_expires_at.isoformat()
                                )
                                session_modified = True
                                logger.debug(
                                    "Stored OBO token with expiration from token claims"
                                )
                except Exception as e:
                    logger.warning(f"Error getting OBO token: {e}")

            if session_modified:
                request.session.modified = True
                logger.debug("All tokens stored successfully")
                return True

            logger.warning("No tokens were stored")
            return False

        except Exception as e:
            logger.warning(f"Error storing tokens in session: {e}")
            return False

    def get_access_token(self, request):
        """
        Get the current access token from the session.

        The token is automatically decrypted before being returned.

        Args:
            request: The current request object

        Returns:
            str: The access token or None if not available
        """
        if not hasattr(request, "session"):
            return None

        if self.using_signed_cookies:
            logger.debug("Token retrieval from signed_cookies session is disabled")
            return None

        encrypted_token = request.session.get(self.ACCESS_TOKEN_KEY)
        return self.decrypt_token(encrypted_token)

    def get_session_obo_access_token(self, request):
        """
        Get the current OBO access token from the session.

        The token is automatically decrypted before being returned.

        Args:
            request: The current request object

        Returns:
            str: The OBO access token or None if not available
        """
        if not hasattr(request, "session"):
            return None

        if self.using_signed_cookies:
            logger.debug("Token retrieval from signed_cookies session is disabled")
            return None

        if not self.store_obo_token:
            logger.debug("OBO token storage is disabled")
            return None

        encrypted_token = request.session.get(self.OBO_ACCESS_TOKEN_KEY)
        return self.decrypt_token(encrypted_token)

    def check_token_expiration(self, request):
        """
        Check if tokens need to be refreshed and refresh them if needed.

        Args:
            request: The current request object

        Returns:
            bool: True if tokens were checked, False otherwise
        """
        if not hasattr(request, "user") or not request.user.is_authenticated:
            return False

        if self.using_signed_cookies:
            return False

        try:
            if self.TOKEN_EXPIRES_AT_KEY not in request.session:
                return False

            # Check if token is about to expire
            expires_at = datetime.datetime.fromisoformat(
                request.session[self.TOKEN_EXPIRES_AT_KEY]
            )
            remaining = expires_at - datetime.datetime.now()

            if remaining.total_seconds() < self.refresh_threshold:
                logger.debug("Token is about to expire. Refreshing...")
                self.refresh_tokens(request)

            # Check if OBO token is about to expire
            if (
                self.store_obo_token
                and self.OBO_TOKEN_EXPIRES_AT_KEY in request.session
            ):
                obo_expires_at = datetime.datetime.fromisoformat(
                    request.session[self.OBO_TOKEN_EXPIRES_AT_KEY]
                )
                obo_remaining = obo_expires_at - datetime.datetime.now()

                if obo_remaining.total_seconds() < self.refresh_threshold:
                    logger.debug("OBO token is about to expire. Refreshing...")
                    self.refresh_obo_token(request)

            return True

        except Exception as e:
            logger.warning(f"Error checking token expiration: {e}")
            return False

    def refresh_tokens(self, request):
        """
        Refresh the access token using the refresh token.

        Args:
            request: The current request object

        Returns:
            bool: True if tokens were refreshed, False otherwise
        """
        if self.using_signed_cookies:
            return False

        if self.REFRESH_TOKEN_KEY not in request.session:
            return False

        try:
            refresh_token = self.decrypt_token(request.session[self.REFRESH_TOKEN_KEY])
            if not refresh_token:
                logger.warning("Failed to decrypt refresh token")
                return False

            provider_config.load_config()

            data = {
                "grant_type": "refresh_token",
                "client_id": settings.CLIENT_ID,
                "refresh_token": refresh_token,
            }

            if settings.CLIENT_SECRET:
                data["client_secret"] = settings.CLIENT_SECRET

            token_endpoint = provider_config.token_endpoint
            if token_endpoint is None:
                logger.error("Token endpoint is None, cannot refresh tokens")
                return False

            response = provider_config.session.post(
                token_endpoint, data=data, timeout=settings.TIMEOUT
            )

            if response.status_code == 200:
                token_data = response.json()

                # Store new tokens - if another refresh happened, these will just overwrite
                # with fresher tokens, which is fine
                request.session[self.ACCESS_TOKEN_KEY] = self.encrypt_token(
                    token_data["access_token"]
                )
                request.session[self.REFRESH_TOKEN_KEY] = self.encrypt_token(
                    token_data["refresh_token"]
                )
                expires_at = datetime.datetime.now() + datetime.timedelta(
                    seconds=int(token_data["expires_in"])
                )
                request.session[self.TOKEN_EXPIRES_AT_KEY] = expires_at.isoformat()
                request.session.modified = True
                logger.debug("Refreshed tokens successfully")

                # Also refresh the OBO token if needed
                if self.store_obo_token:
                    self.refresh_obo_token(request)

                return True
            else:
                logger.warning(
                    f"Failed to refresh token: {response.status_code} {response.text}"
                )
                if self.logout_on_refresh_failure:
                    logger.info("Logging out user due to token refresh failure")
                    logout(request)
                return False

        except Exception as e:
            logger.exception(f"Error refreshing tokens: {e}")
            if self.logout_on_refresh_failure:
                logger.info("Logging out user due to token refresh error")
                logout(request)
            return False

    def refresh_obo_token(self, request):
        """
        Refresh the OBO token for Microsoft Graph API.

        Args:
            request: The current request object

        Returns:
            bool: True if OBO token was refreshed, False otherwise
        """
        if not self.store_obo_token:
            return False

        if self.using_signed_cookies:
            return False

        if self.ACCESS_TOKEN_KEY not in request.session:
            return False

        try:
            provider_config.load_config()

            access_token = self.decrypt_token(request.session[self.ACCESS_TOKEN_KEY])
            if not access_token:
                logger.warning("Failed to decrypt access token")
                return False

            obo_token = self.get_obo_access_token(access_token)

            if obo_token:
                request.session[self.OBO_ACCESS_TOKEN_KEY] = self.encrypt_token(
                    obo_token
                )
                # Decode the OBO token to get its actual expiration time
                import jwt

                decoded_token = jwt.decode(
                    obo_token, options={"verify_signature": False}
                )
                if "exp" in decoded_token:
                    obo_expires_at = datetime.datetime.fromtimestamp(
                        decoded_token["exp"]
                    )
                    request.session[self.OBO_TOKEN_EXPIRES_AT_KEY] = (
                        obo_expires_at.isoformat()
                    )
                    request.session.modified = True
                    logger.debug(
                        "Refreshed OBO token with expiration from token claims"
                    )
                return True

            return False

        except Exception as e:
            logger.warning(f"Error refreshing OBO token: {e}")
            return False

    def clear_tokens(self, request):
        """
        Clear all tokens from the session.

        Args:
            request: The current request object

        Returns:
            bool: True if tokens were cleared, False otherwise
        """
        if not hasattr(request, "session"):
            return False

        try:
            session_modified = False

            for key in [
                self.ACCESS_TOKEN_KEY,
                self.REFRESH_TOKEN_KEY,
                self.TOKEN_EXPIRES_AT_KEY,
                self.OBO_ACCESS_TOKEN_KEY,
                self.OBO_TOKEN_EXPIRES_AT_KEY,
            ]:
                if key in request.session:
                    del request.session[key]
                    session_modified = True

            if session_modified:
                request.session.modified = True
                logger.debug("Cleared tokens from session")
                return True

            return False

        except Exception as e:
            logger.warning(f"Error clearing tokens from session: {e}")
            return False

    def _ms_request(self, action, url, data=None, **kwargs):
        """
        Make a Microsoft Entra/GraphQL request


        Args:
            action (callable): The callable for making a request.
            url (str): The URL the request should be sent to.
            data (dict): Optional dictionary of data to be sent in the request.

        Returns:
            response: The response from the server. If it's not a 200, a
                      PermissionDenied is raised.
        """
        response = action(url, data=data, timeout=settings.TIMEOUT, **kwargs)
        # 200 = valid token received
        # 400 = 'something' is wrong in our request
        if response.status_code == 400:
            if response.json().get("error_description", "").startswith("AADSTS50076"):
                raise MFARequired
            logger.error(
                "ADFS server returned an error: %s",
                response.json()["error_description"],
            )
            raise PermissionDenied

        if response.status_code != 200:
            logger.error("Unexpected ADFS response: %s", response.content.decode())
            raise PermissionDenied
        return response

    def exchange_auth_code(self, authorization_code, request):
        logger.debug("Received authorization code: %s", authorization_code)
        data = {
            "grant_type": "authorization_code",
            "client_id": settings.CLIENT_ID,
            "redirect_uri": provider_config.redirect_uri(request),
            "code": authorization_code,
        }
        if settings.CLIENT_SECRET:
            data["client_secret"] = settings.CLIENT_SECRET

        logger.debug("Getting access token at: %s", provider_config.token_endpoint)
        response = self._ms_request(
            provider_config.session.post, provider_config.token_endpoint, data
        )
        adfs_response = response.json()
        return adfs_response

    def get_obo_access_token(self, access_token):
        """
        Gets an On Behalf Of (OBO) access token, which is required to make queries against MS Graph

        Args:
            access_token (str): Original authorization access token from the user

        Returns:
            obo_access_token (str): OBO access token that can be used with the MS Graph API
        """
        logger.debug("Getting OBO access token: %s", provider_config.token_endpoint)
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "client_id": settings.CLIENT_ID,
            "client_secret": settings.CLIENT_SECRET,
            "assertion": access_token,
            "requested_token_use": "on_behalf_of",
        }
        if provider_config.token_endpoint is None:
            logger.error("Token endpoint is None, cannot get OBO token")
            return None

        if provider_config.token_endpoint.endswith("/v2.0/token"):
            data["scope"] = "GroupMember.Read.All"
        else:
            data["resource"] = "https://graph.microsoft.com"

        response = self._ms_request(
            provider_config.session.get, provider_config.token_endpoint, data
        )
        obo_access_token = response.json()["access_token"]
        logger.debug("Received OBO access token: %s", obo_access_token)
        return obo_access_token

    def get_group_memberships_from_ms_graph_params(self):
        """
        Return the parameters to be used in the querystring
        when fetching the user's group memberships.

        Possible keys to be used:
            - $count
            - $expand
            - $filter
            - $orderby
            - $search
            - $select
            - $top

        Docs:
            https://learn.microsoft.com/en-us/graph/api/group-list-transitivememberof?view=graph-rest-1.0&tabs=python#http-request
        """
        return {}

    def get_group_memberships_from_ms_graph(self, obo_access_token):
        """
        Looks up a users group membership from the MS Graph API

        Args:
            obo_access_token (str): Access token obtained from the OBO authorization endpoint

        Returns:
            claim_groups (list): List of the users group memberships
        """
        graph_url = (
            "https://{}/v1.0/me/transitiveMemberOf/microsoft.graph.group".format(
                provider_config.msgraph_endpoint
            )
        )
        headers = {"Authorization": "Bearer {}".format(obo_access_token)}
        response = self._ms_request(
            action=provider_config.session.get,
            url=graph_url,
            data=self.get_group_memberships_from_ms_graph_params(),
            headers=headers,
        )
        claim_groups = []
        for group_data in response.json()["value"]:
            if group_data["displayName"] is None:
                logger.error(
                    "The application does not have the required permission to read user groups from "
                    "MS Graph (GroupMember.Read.All)"
                )
                raise PermissionDenied

            claim_groups.append(group_data["displayName"])
        return claim_groups

    def validate_access_token(self, access_token):
        for idx, key in enumerate(provider_config.signing_keys):
            try:
                # Explicitly define the verification option.
                # The list below is the default the jwt module uses.
                # Explicit is better then implicit and it protects against
                # changes in the defaults the jwt module uses.
                options = {
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "require_exp": False,
                    "require_iat": False,
                    "require_nbf": False,
                }
                # Validate token and return claims
                return jwt.decode(
                    access_token,
                    key=key,
                    algorithms=["RS256", "RS384", "RS512"],
                    audience=settings.AUDIENCE,
                    issuer=provider_config.issuer,
                    options=options,
                    leeway=settings.JWT_LEEWAY,
                )
            except jwt.ExpiredSignatureError as error:
                logger.info("Signature has expired: %s", error)
                raise PermissionDenied
            except jwt.DecodeError as error:
                # If it's not the last certificate in the list, skip to the next one
                if idx < len(provider_config.signing_keys) - 1:
                    continue
                else:
                    logger.info("Error decoding signature: %s", error)
                    raise PermissionDenied
            except jwt.InvalidTokenError as error:
                logger.info(str(error))
                raise PermissionDenied

    def process_access_token(self, access_token, adfs_response=None, request=None):
        if not access_token:
            raise PermissionDenied

        logger.debug("Received access token: %s", access_token)
        claims = self.validate_access_token(access_token)
        if settings.BLOCK_GUEST_USERS and claims.get("tid") != settings.TENANT_ID:
            logger.info("Guest user denied")
            raise PermissionDenied
        if not claims:
            raise PermissionDenied

        # Store tokens in session if middleware is enabled
        if request and adfs_response and hasattr(request, "token_storage"):
            request.token_storage.store_tokens(request, access_token, adfs_response)

        groups = self.process_user_groups(claims, access_token)
        user = self.create_user(claims)
        self.update_user_attributes(user, claims)
        self.update_user_groups(user, groups)
        self.update_user_flags(user, claims, groups)

        signals.post_authenticate.send(
            sender=self, user=user, claims=claims, adfs_response=adfs_response
        )

        user.full_clean()
        user.save()
        return user

    def process_user_groups(self, claims, access_token):
        """
        Checks the user groups are in the claim or pulls them from MS Graph if
        applicable

        Args:
            claims (dict): claims from the access token
            access_token (str): Used to make an OBO authentication request if
            groups must be obtained from Microsoft Graph

        Returns:
            groups (list): Groups the user is a member of, taken from the access token or MS Graph
        """
        groups = []
        if settings.GROUPS_CLAIM is None:
            logger.debug("No group claim has been configured")
            return groups

        if settings.GROUPS_CLAIM in claims:
            groups = claims[settings.GROUPS_CLAIM]
            if not isinstance(groups, list):
                groups = [
                    groups,
                ]
        elif (
            settings.TENANT_ID != "adfs"
            and "_claim_names" in claims
            and settings.GROUPS_CLAIM in claims["_claim_names"]
        ):
            obo_access_token = self.get_obo_access_token(access_token)
            groups = self.get_group_memberships_from_ms_graph(obo_access_token)
        else:
            logger.debug(
                "The configured groups claim %s was not found in the access token",
                settings.GROUPS_CLAIM,
            )

        return groups

    def create_user(self, claims):
        """
        Create the user if it doesn't exist yet

        Args:
            claims (dict): claims from the access token

        Returns:
            django.contrib.auth.models.User: A Django user
        """
        # Create the user
        username_claim = settings.USERNAME_CLAIM
        guest_username_claim = settings.GUEST_USERNAME_CLAIM
        usermodel = get_user_model()

        iss = claims.get("iss")
        idp = claims.get("idp", iss)
        if (
            guest_username_claim
            and not claims.get(username_claim)
            and not settings.BLOCK_GUEST_USERS
            and (claims.get("tid") != settings.TENANT_ID or iss != idp)
        ):
            username_claim = guest_username_claim

        if not claims.get(username_claim):
            logger.error(
                "User claim's doesn't have the claim '%s' in his claims: %s"
                % (username_claim, claims)
            )
            raise PermissionDenied

        userdata = {usermodel.USERNAME_FIELD: claims[username_claim]}

        try:
            user = usermodel.objects.get(**userdata)
        except usermodel.DoesNotExist:
            if settings.CREATE_NEW_USERS:
                user = usermodel.objects.create(**userdata)
                logger.debug("User '%s' has been created.", claims[username_claim])
            else:
                logger.debug(
                    "User '%s' doesn't exist and creating users is disabled.",
                    claims[username_claim],
                )
                raise PermissionDenied
        if not user.password:
            user.set_unusable_password()
        return user

    # https://github.com/tnware/django-entra-auth/issues/241
    def update_user_attributes(self, user, claims, claim_mapping=None):
        """
        Updates user attributes based on the CLAIM_MAPPING setting.

        Recursively updates related fields if CLAIM_MAPPING settings has
        nested dictionaries.

        Args:
            user (django.contrib.auth.models.User): User model instance
            claims (dict): claims from the access token
        """
        if claim_mapping is None:
            claim_mapping = settings.CLAIM_MAPPING
        required_fields = [
            field.name
            for field in user._meta.get_fields()
            if getattr(field, "blank", True) is False
        ]

        for field, claim in claim_mapping.items():
            if hasattr(user, field) or user._meta.fields_map.get(field):
                if not isinstance(claim, dict):
                    if claim in claims:
                        setattr(user, field, claims[claim])
                        logger.debug(
                            "Attribute '%s' for instance '%s' was set to '%s'.",
                            field,
                            user,
                            claims[claim],
                        )
                    else:
                        if field in required_fields:
                            msg = "Claim not found in access token: '{}'. Check ADFS claims mapping."
                            raise ImproperlyConfigured(msg.format(claim))
                        else:
                            logger.warning(
                                "Claim '%s' for field '%s' was not found in "
                                "the access token for instance '%s'. "
                                "Field is not required and will be left empty",
                                claim,
                                field,
                                user,
                            )
                else:
                    try:
                        self.update_user_attributes(
                            getattr(user, field), claims, claim_mapping=claim
                        )
                    except ObjectDoesNotExist:
                        logger.warning(
                            "Object for field '{}' does not exist for: '{}'.".format(
                                field, user
                            )
                        )

            else:
                msg = "Model '{}' has no field named '{}'. Check ADFS claims mapping."
                raise ImproperlyConfigured(msg.format(user._meta.model_name, field))

    def update_user_groups(self, user, claim_groups):
        """
        Updates user group memberships based on the GROUPS_CLAIM setting.

        Args:
            user (django.contrib.auth.models.User): User model instance
            claim_groups (list): User groups from the access token / MS Graph
        """
        if settings.GROUPS_CLAIM is not None:
            # Update the user's group memberships
            user_group_names = user.groups.all().values_list("name", flat=True)

            if sorted(claim_groups) != sorted(user_group_names):
                # Get the list of already existing groups in one SQL query
                existing_claimed_groups = Group.objects.filter(name__in=claim_groups)

                if settings.MIRROR_GROUPS:
                    existing_claimed_group_names = (
                        group.name for group in existing_claimed_groups
                    )
                    # One SQL query by created group.
                    # bulk_create could have been used here but we want to send signals.
                    new_claimed_groups = [
                        Group.objects.get_or_create(name=name)[0]
                        for name in claim_groups
                        if name not in existing_claimed_group_names
                    ]
                    # Associate the users to all claimed groups
                    user.groups.set(
                        tuple(existing_claimed_groups) + tuple(new_claimed_groups)
                    )
                else:
                    # Associate the user to only existing claimed groups
                    user.groups.set(existing_claimed_groups)

    def update_user_flags(self, user, claims, claim_groups):
        """
        Updates user boolean attributes based on the BOOLEAN_CLAIM_MAPPING setting.

        Args:
            user (django.contrib.auth.models.User): User model instance
            claims (dict): Claims from the access token
            claim_groups (list): User groups from the access token / MS Graph
        """
        if settings.GROUPS_CLAIM is not None:
            for flag, group in settings.GROUP_TO_FLAG_MAPPING.items():
                if hasattr(user, flag):
                    if not isinstance(group, list):
                        group = [group]

                    if any(
                        group_list_item in claim_groups for group_list_item in group
                    ):
                        value = True
                    else:
                        value = False
                    setattr(user, flag, value)
                    logger.debug(
                        "Attribute '%s' for user '%s' was set to '%s'.",
                        flag,
                        user,
                        value,
                    )
                else:
                    msg = "User model has no field named '{}'. Check ADFS boolean claims mapping."
                    raise ImproperlyConfigured(msg.format(flag))

        for field, claim in settings.BOOLEAN_CLAIM_MAPPING.items():
            if hasattr(user, field):
                bool_val = False
                if claim in claims and str(claims[claim]).lower() in [
                    "y",
                    "yes",
                    "t",
                    "true",
                    "on",
                    "1",
                ]:
                    bool_val = True
                setattr(user, field, bool_val)
                logger.debug(
                    "Attribute '%s' for user '%s' was set to '%s'.",
                    field,
                    user,
                    bool_val,
                )
            else:
                msg = "User model has no field named '{}'. Check ADFS boolean claims mapping."
                raise ImproperlyConfigured(msg.format(field))


class AdfsAuthCodeBackend(AdfsBaseBackend):
    """
    Authentication backend to allow authenticating users against a
    Microsoft ADFS server with an authorization code.
    """

    def authenticate(self, request=None, authorization_code=None, **kwargs):
        # If there's no token or code, we pass control to the next authentication backend
        if authorization_code is None or authorization_code == "":
            logger.debug(
                "Authentication backend was called but no authorization code was received"
            )
            return

        # If loaded data is too old, reload it again
        provider_config.load_config()

        adfs_response = self.exchange_auth_code(authorization_code, request)
        access_token = adfs_response["access_token"]
        user = self.process_access_token(access_token, adfs_response, request)
        return user


class AdfsAccessTokenBackend(AdfsBaseBackend):
    """
    Authentication backend to allow authenticating users against a
    Microsoft ADFS server with an access token retrieved by the client.
    """

    def authenticate(self, request=None, access_token=None, **kwargs):
        # If loaded data is too old, reload it again
        provider_config.load_config()

        # If there's no token or code, we pass control to the next authentication backend
        if access_token is None or access_token == "":
            logger.debug(
                "Authentication backend was called but no access token was received"
            )
            return

        access_token = access_token.decode()
        user = self.process_access_token(access_token, request=request)
        return user


class AdfsBackend(AdfsAuthCodeBackend):
    """Backwards compatible class name"""

    pass
