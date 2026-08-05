# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import os
from urllib.parse import urlencode

# Django imports
from django.contrib.auth import logout
from django.http import HttpResponseRedirect
from django.utils import timezone
from django.views import View

# Module imports
from plane.authentication.utils.host import base_host, user_ip
from plane.db.models import Account, User


class SignOutAuthEndpoint(View):
    def post(self, request):
        try:
            user = User.objects.get(pk=request.user.id)
            user.last_logout_ip = user_ip(request=request)
            user.last_logout_time = timezone.now()
            was_keycloak_user = user.last_login_medium == "keycloak"
            user.save()
            logout(request)

            app_base = base_host(request=request, is_app=True)

            # Redirect to Keycloak end-session endpoint if user logged in via Keycloak
            if was_keycloak_user:
                keycloak_url = os.environ.get("KEYCLOAK_URL", "")
                keycloak_realm = os.environ.get("KEYCLOAK_REALM", "")
                if keycloak_url and keycloak_realm:
                    end_session_url = (
                        f"{keycloak_url.rstrip('/')}/realms/{keycloak_realm}"
                        f"/protocol/openid-connect/logout"
                    )
                    logout_params = {"post_logout_redirect_uri": app_base}
                    account = Account.objects.filter(user=user, provider="keycloak").first()
                    if account and account.id_token:
                        logout_params["id_token_hint"] = account.id_token
                    return HttpResponseRedirect(f"{end_session_url}?{urlencode(logout_params)}")

            return HttpResponseRedirect(app_base)
        except Exception:
            return HttpResponseRedirect(base_host(request=request, is_app=True))
