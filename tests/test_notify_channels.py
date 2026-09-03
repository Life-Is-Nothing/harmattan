"""Tests for notification channel dispatchers."""
from __future__ import annotations

import json
from unittest.mock import Mock, patch

import pytest


SAMPLE_EVENT = {
    "type": "test.event",
    "title": "Test Alert",
    "message": "This is a test notification",
    "severity": "haute",
    "ts": "2026-07-20T12:00:00",
}


class TestSlackNotify:
    def test_slack_send_success(self):
        from core.notify_slack import send
        with patch("core.notify_slack.requests.post") as mock_post:
            mock_post.return_value = Mock(ok=True, raise_for_status=lambda: None)
            result = send("https://hooks.slack.com/test", "test.event", SAMPLE_EVENT)
            assert result is True
            mock_post.assert_called_once()

    def test_slack_send_failure(self):
        from core.notify_slack import send
        import requests
        with patch("core.notify_slack.requests.post") as mock_post:
            mock_post.side_effect = requests.exceptions.ConnectionError("Connection error")
            result = send("https://hooks.slack.com/test", "test.event", SAMPLE_EVENT)
            assert result is False

    def test_slack_send_includes_blocks(self):
        from core.notify_slack import send
        with patch("core.notify_slack.requests.post") as mock_post:
            mock_post.return_value = Mock(ok=True, raise_for_status=lambda: None)
            send("https://hooks.slack.com/test", "test.event", SAMPLE_EVENT)
            call_kwargs = mock_post.call_args[1]
            data = call_kwargs["json"]
            assert "attachments" in data


class TestDiscordNotify:
    def test_discord_send_success(self):
        from core.notify_discord import send
        with patch("core.notify_discord.requests.post") as mock_post:
            mock_post.return_value = Mock(ok=True, raise_for_status=lambda: None)
            result = send("https://discord.com/webhook/test", "test.event", SAMPLE_EVENT)
            assert result is True

    def test_discord_send_failure(self):
        from core.notify_discord import send
        import requests
        with patch("core.notify_discord.requests.post") as mock_post:
            mock_post.side_effect = requests.exceptions.ConnectionError("Timeout")
            result = send("https://discord.com/webhook/test", "test.event", SAMPLE_EVENT)
            assert result is False

    def test_discord_send_includes_embeds(self):
        from core.notify_discord import send
        with patch("core.notify_discord.requests.post") as mock_post:
            mock_post.return_value = Mock(ok=True, raise_for_status=lambda: None)
            send("https://discord.com/webhook/test", "test.event", SAMPLE_EVENT)
            call_kwargs = mock_post.call_args[1]
            data = call_kwargs["json"]
            assert "embeds" in data


class TestEmailNotify:
    def test_email_no_recipients(self):
        from core.notify_email import send
        result = send("", "test.event", SAMPLE_EVENT, {"to": ""})
        assert result is False

    def test_email_with_recipients(self):
        from core.notify_email import send
        with patch("core.notify_email.smtplib.SMTP") as mock_smtp:
            instance = Mock()
            mock_smtp.return_value = instance
            result = send("", "test.event", SAMPLE_EVENT,
                          {"to": "admin@test.com", "smtp_host": "localhost", "smtp_port": "25"})
            assert result is True


class TestSyslogNotify:
    def test_syslog_send(self):
        from core.notify_syslog import send
        result = send("", "test.event", SAMPLE_EVENT, {"syslog_host": "localhost"})
        assert result is True
