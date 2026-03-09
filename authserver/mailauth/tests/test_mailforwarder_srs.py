from types import SimpleNamespace
from typing import Any, List, Sequence, Tuple
from unittest import mock

from django.test import SimpleTestCase

from maildaemons.forwarder.server import ForwarderServer


class _FakeExistsQuery:
    def __init__(self, value: bool) -> None:
        self._value = value

    def exists(self) -> bool:
        return self._value


class _FakeDomain:
    class DoesNotExist(Exception):
        pass

    class Manager:
        @staticmethod
        def get(name: str) -> Any:
            raise _FakeDomain.DoesNotExist()

    objects = Manager()


class _FakeEmailAlias:
    class DoesNotExist(Exception):
        pass

    objects = None  # type: Any


class _FakeEmailAliasManager:
    def __init__(self, alias: Any) -> None:
        self.alias = alias

    def filter(self, **kwargs: Any) -> _FakeExistsQuery:
        return _FakeExistsQuery(False)

    def get(self, **kwargs: Any) -> Any:
        return self.alias


class ForwarderSRSTests(SimpleTestCase):
    def _build_server(self, srs_secret: str = "") -> Tuple[ForwarderServer, List[Tuple[str, Sequence[str], bytes]]]:
        server = ForwarderServer(
            localaddr=("127.0.0.1", 10046),
            daemon_name="mailforwarder",
            remote_relay=("127.0.0.1", 10045),
            transactional_relay=("127.0.0.1", 10045),
            local_delivery=("127.0.0.1", 10045),
            srs_secret=srs_secret,
        )
        sent = []  # type: List[Tuple[str, Sequence[str], bytes]]
        server.add_received_header = lambda peer, helo_name, data: data  # type: ignore[assignment]
        server.smtp.sendmail = lambda from_addr, to_addrs, msg, *args, **kwargs: sent.append(  # type: ignore[assignment]
            (from_addr, to_addrs, msg)
        ) or None
        return server, sent

    def test_process_message_uses_list_mailfrom_when_set(self) -> None:
        alias = SimpleNamespace(
            forward_to=SimpleNamespace(
                new_mailfrom="bounces@forward.example",
                addresses=["ops@example.net"],
            ),
            domain=SimpleNamespace(name="example.com"),
        )
        _FakeEmailAlias.objects = _FakeEmailAliasManager(alias)
        server, sent = self._build_server(srs_secret="")

        with mock.patch("mailauth.models.EmailAlias", _FakeEmailAlias), \
                mock.patch("mailauth.models.Domain", _FakeDomain):
            ret = server._process_message(
                peer=("127.0.0.1", 25000),
                helo_name="mx.sender.example",
                mailfrom="alice@sender.example",
                rcpttos=["team@example.com"],
                data=b"Subject: test\r\n\r\nhello",
            )

        self.assertEqual("250 Processing complete.", ret)
        self.assertEqual(1, len(sent))
        self.assertEqual("bounces@forward.example", sent[0][0])
        self.assertEqual(["ops@example.net"], list(sent[0][1]))

    def test_process_message_uses_srs_when_list_mailfrom_not_set(self) -> None:
        alias = SimpleNamespace(
            forward_to=SimpleNamespace(
                new_mailfrom="",
                addresses=["ops@example.net"],
            ),
            domain=SimpleNamespace(name="example.com"),
        )
        _FakeEmailAlias.objects = _FakeEmailAliasManager(alias)
        server, sent = self._build_server(srs_secret="topsecret")

        with mock.patch("mailauth.models.EmailAlias", _FakeEmailAlias), \
                mock.patch("mailauth.models.Domain", _FakeDomain):
            ret = server._process_message(
                peer=("127.0.0.1", 25000),
                helo_name="mx.sender.example",
                mailfrom="alice@sender.example",
                rcpttos=["team@example.com"],
                data=b"Subject: test\r\n\r\nhello",
            )

        self.assertEqual("250 Processing complete.", ret)
        self.assertEqual(1, len(sent))
        self.assertTrue(sent[0][0].startswith("SRS0="), "Expected SRS-rewritten mailfrom, got: %s" % sent[0][0])
        self.assertEqual(["ops@example.net"], list(sent[0][1]))

    def test_process_message_list_mailfrom_overrides_srs_when_set(self) -> None:
        alias = SimpleNamespace(
            forward_to=SimpleNamespace(
                new_mailfrom="bounces@forward.example",
                addresses=["ops@example.net"],
            ),
            domain=SimpleNamespace(name="example.com"),
        )
        _FakeEmailAlias.objects = _FakeEmailAliasManager(alias)
        server, sent = self._build_server(srs_secret="topsecret")

        with mock.patch("mailauth.models.EmailAlias", _FakeEmailAlias), \
                mock.patch("mailauth.models.Domain", _FakeDomain):
            ret = server._process_message(
                peer=("127.0.0.1", 25000),
                helo_name="mx.sender.example",
                mailfrom="alice@sender.example",
                rcpttos=["team@example.com"],
                data=b"Subject: test\r\n\r\nhello",
            )

        self.assertEqual("250 Processing complete.", ret)
        self.assertEqual(1, len(sent))
        self.assertEqual("bounces@forward.example", sent[0][0])
        self.assertEqual(["ops@example.net"], list(sent[0][1]))
