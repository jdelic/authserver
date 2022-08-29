from datetime import datetime
from typing import List, Dict
from zoneinfo import ZoneInfo

from django.http import HttpRequest
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.scopes import BaseScopes

from mailauth.models import MNApplication


USER_SCOPES = [
    "openid",
    "profile",
    "email",
    "address",
    "phone",
]


class MNAuthScopes(BaseScopes):
    def get_available_scopes(self, application: MNApplication = None, request: HttpRequest = None,
                             *args, **kwargs) -> List[str]:
        return USER_SCOPES

    def get_all_scopes(self) -> Dict[str, str]:
        return {
            sc: "" for sc in USER_SCOPES
        }

    def get_default_scopes(self, application: MNApplication = None,
                           request: HttpRequest = None, *args, **kwargs) -> List[str]:
        return USER_SCOPES
