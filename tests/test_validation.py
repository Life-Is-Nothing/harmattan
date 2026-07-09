import pytest

from core.validation import (
    ValidationError,
    sanitize_nmap_custom_args,
    validate_cidr,
    validate_ip,
    validate_port,
    validate_target,
)


def test_validate_ip_ok():
    assert validate_ip("192.168.1.1") == "192.168.1.1"


def test_validate_ip_bad():
    with pytest.raises(ValidationError):
        validate_ip("not-an-ip")


def test_validate_cidr():
    assert "192.168.0.0/24" in validate_cidr("192.168.0.0/24")


def test_cidr_too_large():
    with pytest.raises(ValidationError):
        validate_cidr("10.0.0.0/8")


def test_nmap_args_safe():
    args = sanitize_nmap_custom_args("-T4 -p 80,443 --open")
    assert "-T4" in args
    assert "-p" in args


def test_nmap_args_reject_shell():
    with pytest.raises(ValidationError):
        sanitize_nmap_custom_args("-T4; id")


def test_nmap_args_reject_unknown():
    with pytest.raises(ValidationError):
        sanitize_nmap_custom_args("--evil-flag")


def test_validate_port():
    assert validate_port(443) == 443
    with pytest.raises(ValidationError):
        validate_port(70000)


def test_validate_target_hostname():
    assert validate_target("example.com") == "example.com"
