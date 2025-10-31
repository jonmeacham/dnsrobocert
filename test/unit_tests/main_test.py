import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from dnsrobocert.core import main


@patch("dnsrobocert.core.main.utils.validate_snap_environment")
@patch("dnsrobocert.core.main.certbot.account")
@patch("dnsrobocert.core.main.certbot.certonly")
@patch("dnsrobocert.core.main.certbot.revoke")
@patch("dnsrobocert.core.main.background")
@patch.object(main._Daemon, "do_shutdown")
def test_main_loop(
    shutdown: MagicMock,
    background: MagicMock,
    revoke: MagicMock,
    certonly: MagicMock,
    account: MagicMock,
    _validate_snap: MagicMock,
    tmp_path: Path,
) -> None:
    directory_path = tmp_path / "letsencrypt"
    os.mkdir(directory_path)

    config_path = tmp_path / "config.yml"
    with open(str(config_path), "w") as f:
        f.write(
            """\
draft: false
acme:
  email_account: john.doe@example.net
profiles:
- name: dummy
  provider: dummy
  provider_options:
    auth_token: TOKEN
certificates:
- domains:
  - test1.example.net
  - test2.example.net
  profile: dummy
"""
        )

    shutdown.side_effect = [False, True]
    main.main(["-c", str(config_path), "-d", str(directory_path)])

    assert shutdown.called
    assert account.called
    assert certonly.called
    assert not revoke.called
    assert background.worker.called


@patch("dnsrobocert.core.main.utils.validate_snap_environment")
@patch("dnsrobocert.core.main.utils.digest")
@patch("dnsrobocert.core.main._stat_signature")
@patch("dnsrobocert.core.main.certbot.account")
@patch("dnsrobocert.core.main.certbot._issue")
@patch("dnsrobocert.core.main.background")
@patch.object(main._Daemon, "wait_or_shutdown")
@patch.object(main._Daemon, "do_shutdown")
def test_polling_skips_digest_when_metadata_unchanged(
    do_shutdown: MagicMock,
    wait_or_shutdown: MagicMock,
    background: MagicMock,
    issue: MagicMock,
    account: MagicMock,
    stat_signature: MagicMock,
    digest: MagicMock,
    _validate_snap: MagicMock,
    tmp_path: Path,
) -> None:
    directory_path = tmp_path / "letsencrypt"
    os.mkdir(directory_path)

    config_path = tmp_path / "config.yml"
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(
            """\
draft: false
acme:
  email_account: john.doe@example.net
profiles:
- name: dummy
  provider: dummy
  provider_options:
    auth_token: TOKEN
certificates:
- domains:
  - test1.example.net
  - test2.example.net
  profile: dummy
"""
        )

    do_shutdown.return_value = False
    wait_or_shutdown.side_effect = [False, True]
    stat_signature.side_effect = [(1, 10), (1, 10)]
    digest.side_effect = [b"digest"]

    with patch("dnsrobocert.core.main._WATCHDOG_AVAILABLE", False):
        main.main(["-c", str(config_path), "-d", str(directory_path)])

    assert digest.call_count == 1
    assert account.call_count == 1
    assert issue.call_count == 1
    wait_or_shutdown.assert_called()
