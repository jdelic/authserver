# -* encoding: utf-8 *-
import base64
import logging
from typing import Dict, Any, Optional

import jwt
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from mailauth.models import MNUser


_log = logging.getLogger(__name__)


class JWTViewHelperMixin:
    def _create_jwt(self, claim: Dict[str, Any], key_pemstr: str) -> str:
        _log.debug("Encoding JWT response: %s", claim)

        fp = base64.b32encode(
            SHA256.new(
                data=RSA.importKey(key_pemstr).publickey().exportKey(format="DER")
            ).digest()[0:30]  # shorten to 240 bit presumably so no padding is necessary
        ).decode('utf-8')

        kid = ":".join([fp[i:i + 4] for i in range(0, len(fp), 4)])

        jwtstr = jwt.encode(
            claim,
            headers={
                "typ": "JWT",
                "alg": "RS256",
                "kid": kid,
            },
            key=key_pemstr,
            algorithm="RS256",
        ).decode('utf-8')

        _log.debug("JWT response: %s", jwtstr)
        return jwtstr

    def _user_from_jwt(self, jwtstr: str, key_pemstr: str, expected_issuer: Optional[str]=None,
                       expected_audience: Optional[str]=None) -> Optional[MNUser]:
        _log.debug("Received refresh token: %s", jwtstr)
        try:
            token = jwt.decode(jwtstr, key_pemstr, algorithms=["RS256"], leeway=10,
                               issuer=expected_issuer, audience=expected_audience)
        except (jwt.ExpiredSignatureError, jwt.InvalidAlgorithmError,
                jwt.InvalidIssuerError, jwt.InvalidTokenError) as e:
            _log.warning("Rejected refresh token because of %s", str(e))
            return None

        if "sub" not in token:
            _log.error("BUG? Valid refresh token without user in subject. %s", jwtstr)
            return None

        try:
            user = MNUser.objects.get(pk=token["sub"])  # type: MNUser
        except MNUser.DoesNotExist:
            _log.warning("No such user from valid JWT. %s", jwtstr)
            return None
        return user
