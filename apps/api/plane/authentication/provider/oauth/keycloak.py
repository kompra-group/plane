# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import os
from datetime import datetime
from urllib.parse import urlencode

import pytz

from plane.authentication.adapter.error import AUTHENTICATION_ERROR_CODES, AuthenticationException
from plane.authentication.adapter.oauth import OauthAdapter
from plane.license.utils.instance_value import get_configuration_value


class KeycloakOAuthProvider(OauthAdapter):
    provider = "keycloak"
    scope = "openid email profile"

    def __init__(self, request, code=None, state=None, callback=None):
        (
            KEYCLOAK_URL,
            KEYCLOAK_REALM,
            KEYCLOAK_CLIENT_ID,
            KEYCLOAK_CLIENT_SECRET,
        ) = get_configuration_value(
            [
                {"key": "KEYCLOAK_URL", "default": os.environ.get("KEYCLOAK_URL", "")},
                {"key": "KEYCLOAK_REALM", "default": os.environ.get("KEYCLOAK_REALM", "")},
                {"key": "KEYCLOAK_CLIENT_ID", "default": os.environ.get("KEYCLOAK_CLIENT_ID", "")},
                {"key": "KEYCLOAK_CLIENT_SECRET", "default": os.environ.get("KEYCLOAK_CLIENT_SECRET", "")},
            ]
        )

        if not all([KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET]):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["KEYCLOAK_NOT_CONFIGURED"],
                error_message="KEYCLOAK_NOT_CONFIGURED",
            )

        self.base_url = f"{KEYCLOAK_URL.rstrip('/')}/realms/{KEYCLOAK_REALM}/protocol/openid-connect"
        token_url = f"{self.base_url}/token"
        userinfo_url = f"{self.base_url}/userinfo"

        redirect_uri = f"""{"https" if request.is_secure() else "http"}://{request.get_host()}/auth/keycloak/callback/"""
        url_params = {
            "client_id": KEYCLOAK_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": self.scope,
            "state": state,
        }
        auth_url = f"{self.base_url}/auth?{urlencode(url_params)}"

        super().__init__(
            request,
            self.provider,
            KEYCLOAK_CLIENT_ID,
            self.scope,
            redirect_uri,
            auth_url,
            token_url,
            userinfo_url,
            KEYCLOAK_CLIENT_SECRET,
            code,
            callback=callback,
        )

    def set_token_data(self):
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": self.code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        token_response = self.get_user_token(data=data, headers={"Accept": "application/json"})
        super().set_token_data(
            {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token"),
                "id_token": token_response.get("id_token", ""),
                "access_token_expired_at": (
                    datetime.fromtimestamp(token_response.get("expires_in"), tz=pytz.utc)
                    if token_response.get("expires_in")
                    else None
                ),
                "refresh_token_expired_at": None,
            }
        )

    def set_user_data(self):
        user_info_response = self.get_user_response()

        # Reject only if explicitly False — some Keycloak configs omit this claim
        if user_info_response.get("email_verified") is False:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OAUTH_PROVIDER_UNVERIFIED_EMAIL"],
                error_message="OAUTH_PROVIDER_UNVERIFIED_EMAIL",
            )

        groups_attr = os.environ.get("OIDC_GROUPS_ATTRIBUTE", "groups")
        groups = user_info_response.get(groups_attr, [])
        if not isinstance(groups, list):
            groups = []

        super().set_user_data(
            {
                "email": user_info_response.get("email"),
                "user": {
                    "provider_id": user_info_response.get("sub"),
                    "first_name": user_info_response.get("given_name", ""),
                    "last_name": user_info_response.get("family_name", ""),
                    "avatar": user_info_response.get("picture", ""),
                    "is_password_autoset": True,
                },
                "groups": groups,
            }
        )

    def complete_login_or_signup(self):
        user = super().complete_login_or_signup()
        # Sync organization from first Keycloak group when OIDC_SYNC_GROUPS is enabled
        if os.environ.get("OIDC_SYNC_GROUPS", "false").lower() in ("true", "1"):
            groups = self.user_data.get("groups", [])
            if groups:
                organization = groups[0].lstrip("/")
                if user.organization != organization:
                    user.organization = organization
                    user.save(update_fields=["organization"])
        return user
