"""Acceptance assertions executed by root inside the disposable Ubuntu guest."""

import copy
import json
import os
import secrets
import signal
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

from ipsecvpn.host import UNIT, Host
from ipsecvpn.installer import GUARD, RESTORE, STATE
from ipsecvpn.profile import load_profile
from ipsecvpn.renderer import build_manifest
from ipsecvpn.resources import Resources
from ipsecvpn.secureio import Stop, read_record
from ipsecvpn.transaction import ACTIVE, BACKUPS, INSTALLED, JOURNAL, Deployment, boot, locked

HERE = Path(__file__).parent
PROFILE = Path("/etc/ipsecvpn/profiles/lab.yaml")
UPDATE = PROFILE.with_name("update.yaml")
SUMMARY = Path("/var/tmp/ipsecvpn-acceptance.jsonl")
BASELINE = Path("/var/tmp/ipsecvpn-lab-baseline.json")
CLI = Path(sys.executable).with_name("ipsecvpn")
HOST = Host()
ENV = {}
KEYS = []


def command(*args, allowed=(0,), data=None):
    proc = subprocess.run(
        args, input=data, text=True, capture_output=True, check=False, timeout=120
    )
    if proc.returncode not in allowed:
        raise RuntimeError(f"{Path(args[0]).name} exit={proc.returncode}")
    return proc


def cli(*args, ok=True):
    proc = command(str(CLI), *args, "--json", allowed=(0,) if ok else (1,))
    output = (proc.stdout + proc.stderr).encode()
    assert all(key not in output and key.hex().encode() not in output for key in KEYS)
    report = json.loads(proc.stdout)
    assert report["status"] == ("PASS" if ok else "FAIL"), report.get("detail")
    if not ok:
        assert report.get("decision") == "STOP", report.get("detail")
    return report


def emit(ids, verdict, expected, observed):
    with SUMMARY.open("a", encoding="utf-8") as stream:
        for case in ids.split():
            row = {
                "case": case,
                "at": datetime.now(UTC).isoformat(),
                "result": verdict,
                "vm": "ipsecvpn-pr2-lab",
                "versions": ENV,
                "expected": expected,
                "observed": observed,
                "evidence": "GitHub job log / ipsecvpn-acceptance.jsonl",
                "system_touched": "isolated VM only",
                "driver": "scripts/pr2-vm/verify.py",
            }
            stream.write(json.dumps(row, sort_keys=True) + "\n")


def profile_write(path, profile):
    path.write_text(yaml.safe_dump(profile), encoding="utf-8")
    path.chmod(0o600)


def resources(*manifests):
    install = read_record(INSTALLED)
    return Resources(HOST, install["token"] if install else "lab-before-install", manifests)


def current_manifest():
    return build_manifest(read_record(ACTIVE)["profile"])


def bootstrap_profiles():
    profile = load_profile(HERE / "example.yaml")
    routes = HOST.ip("-4", "route", "show", "default")
    assert routes, "Isolated VM baseline is missing its synthetic default route."
    default = routes[0]
    wan = default["dev"]
    addr = HOST.ip("-4", "addr", "show", "dev", wan)[0]["addr_info"][0]["local"]
    for link in profile["site_links"]:
        link["outer_path"].update(interface=wan, source_ip=addr, gateway=default["gateway"])
        path = Path(link["secret_ref"][5:])
        key = secrets.token_hex(32).encode("ascii")
        KEYS.append(key)
        path.write_bytes(key + b"\n")
        path.chmod(0o600)
    profile["backup"] = {"enabled": True, "type": "external_managed"}
    profile_write(PROFILE, profile)
    update = copy.deepcopy(profile)
    update["site_links"][1]["if_id"] += 100
    update["sites"][1]["lan_cidrs"] = ["10.77.12.0/24"]
    update["sites"][1]["public_endpoint"] = "198.51.100.77"
    profile_write(UPDATE, update)
    return profile


class FaultHost(Host):
    def __init__(self, label, crash=False):
        super().__init__()
        self.label, self.crash, self.fired = label, crash, False

    def command(self, label, *args, **kwargs):
        if kwargs.get("mutate") and label == self.label and not self.fired:
            self.fired = True
            if self.crash:
                super().command(label, *args, **kwargs)
                os.kill(os.getpid(), signal.SIGKILL)
            return super().command(
                label, args[0], "--ipsecvpn-injected-invalid-option", mutate=True
            )
        return super().command(label, *args, **kwargs)


def check_failure(label, manifest, baseline):
    faulty = FaultHost(label)
    try:
        Deployment(faulty).dispatch("apply", True, UPDATE)
    except Stop:
        assert faulty.fired
    else:
        raise AssertionError("Injected failure did not stop the transaction.")
    assert read_record(JOURNAL)["phase"] == "RESTORED"
    resources(manifest).verify(manifest, baseline, read_record(ACTIVE)["nft_sha256"])


def negative_cases(profile, manifest, baseline):
    expected = "apply --confirm exits FAIL/STOP without changing project or foreign resources"

    def stopped(case, label, path=PROFILE, match=None):
        result = cli("apply", "-c", str(path), "--confirm", ok=False)
        if match:
            assert match in result["detail"], result["detail"]
        emit(case, "PASS", expected, label)

    link = manifest.links[0]
    command("ip", "link", "add", "name", "labcollision", "type", "xfrm", "if_id", str(link.if_id))
    try:
        stopped("F02", "Existing XFRM ID detected.", match="XFRM")
        assert HOST.ip("link", "show", "dev", "labcollision")
    finally:
        command("ip", "link", "del", "dev", "labcollision")
    network = link.remote_ts[0]
    host_route = network.split("/")[0] + "/32"
    for cidr, case in ((network, "F03"), (host_route, "F12")):
        command("ip", "route", "add", "blackhole", cidr, "proto", "static")
        try:
            stopped(case, "Conflicting route retained.", match="overlaps")
        finally:
            command("ip", "route", "del", "blackhole", cidr, "proto", "static")
    command("ip", "rule", "add", "priority", "100", "lookup", "main")
    try:
        stopped("F12", "Unmanaged policy rule rejected.", match="policy routing")
    finally:
        command("ip", "rule", "del", "priority", "100", "lookup", "main")

    draft = PROFILE.with_name("negative.yaml")
    wrong = copy.deepcopy(profile)
    wrong["site_links"][0]["outer_path"]["gateway"] = "192.0.2.253"
    profile_write(draft, wrong)
    stopped("F04", "Peer lookup rejected mismatched gateway.", draft, "WAN path")

    command(
        "nft",
        "-f",
        "-",
        data=(
            "table ip lab_block { chain forward { "
            "type filter hook forward priority 0; policy drop; } }\n"
        ),
    )
    try:
        stopped("F05", "Foreign forward DROP was preserved.", match="foreign firewall")
        command("nft", "list", "table", "ip", "lab_block")
    finally:
        command("nft", "delete", "table", "ip", "lab_block")

    secret = Path(profile["site_links"][0]["secret_ref"][5:])
    real = secret.with_suffix(".saved")
    secret.rename(real)
    try:
        stopped("F07", "Missing IKE key rejected.", match="IKE key")
        secret.symlink_to(real)
        stopped("F07", "Symlink rejected.", match="IKE key")
        secret.unlink()
        os.link(real, secret)
        stopped("F07", "Hardlink rejected.", match="protected file")
        secret.unlink()
    finally:
        secret.unlink(missing_ok=True)
        real.rename(secret)
    secret.chmod(0o644)
    try:
        stopped("F07", "Insecure key mode rejected.", match="protected file")
    finally:
        secret.chmod(0o600)
    os.chown(secret, 65534, 65534)
    try:
        stopped("F07", "Non-root key owner rejected.", match="protected file")
    finally:
        os.chown(secret, 0, 0)

    nonroot = command(
        "runuser", "-u", "nobody", "--", str(CLI), "install", "--confirm", allowed=(1,)
    )
    assert "FAIL/STOP" in nonroot.stderr
    emit("F09", "PASS", "Non-root host write exits STOP.", "Exit 1 before work.")
    malformed = copy.deepcopy(profile)
    malformed["default_route"] = "192.0.2.1"
    profile_write(draft, malformed)
    assert "Schema violation" in command(str(CLI), "render", "-c", str(draft), allowed=(1,)).stdout
    malformed = copy.deepcopy(profile)
    malformed["site_links"][0]["outer_path"]["interface"] = "eth0;echo invalid"
    profile_write(draft, malformed)
    assert "Schema violation" in command(str(CLI), "render", "-c", str(draft), allowed=(1,)).stdout
    emit(
        "F06 F13",
        "PASS",
        "Reject foreign configuration fields and injected syntax.",
        "Schema rejected both before execution.",
    )
    assert resources().baseline() == baseline


def before_reboot():
    ENV.update(HOST.probe(), nft=command("nft", "--version").stdout.strip())
    profile = bootstrap_profiles()
    manifest = build_manifest(profile)
    baseline = resources().baseline()
    BASELINE.write_text(json.dumps(baseline), encoding="utf-8")
    emit(
        "V01",
        "PASS",
        "Ubuntu/kernel/VM and nft/XFRM probe succeeds.",
        "Read-only host probes succeeded.",
    )

    foreign = Path("/etc/swanctl")
    foreign.mkdir()
    marker = foreign / "foreign.conf"
    marker.write_text("# isolated fixture\n", encoding="ascii")
    try:
        assert "unowned" in cli("install", "--confirm", ok=False)["detail"]
        assert marker.read_text(encoding="ascii") == "# isolated fixture\n"
    finally:
        marker.unlink()
        foreign.rmdir()
    emit("F08", "PASS", "Existing swanctl config is preserved.", "STOP with file unchanged.")
    listener = subprocess.Popen(
        (
            sys.executable,
            "-c",
            "import socket,time;s=socket.socket(2,2);s.bind(('0.0.0.0',500));"
            "print('ready',flush=True);time.sleep(30)",
        ),
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert listener.stdout.readline().strip() == "ready"
        assert "unowned" in cli("install", "--confirm", ok=False)["detail"]
        assert listener.poll() is None
    finally:
        listener.terminate()
        listener.wait(timeout=10)
    emit(
        "F01",
        "PASS",
        "Occupied UDP/500 yields STOP with original owner alive.",
        "Unrelated listener remained.",
    )

    packages = HOST.packages()
    state_before = sorted(path.name for path in STATE.iterdir()) if STATE.exists() else []
    cli("install", "--dry-run")
    assert HOST.packages() == packages and resources().baseline() == baseline
    assert (sorted(path.name for path in STATE.iterdir()) if STATE.exists() else []) == state_before
    emit(
        "V02",
        "PASS",
        "Dry-run preserves packages, files and networking.",
        "Package and state inventories matched.",
    )
    installed = cli("install", "--confirm")
    ENV["strongswan"] = HOST.packages()["charon-systemd"]
    assert installed["baseline_unchanged"] and HOST.vici_names() == set()
    emit(
        "V03",
        "PASS",
        "Install only planned packages and start owned VICI daemon.",
        installed["packages"],
    )

    negative_cases(profile, manifest, baseline)
    initial = cli("apply", "-c", str(PROFILE), "--dry-run")
    assert len(initial["diff"]["add"]) == 2 and read_record(ACTIVE) is None
    assert resources().baseline() == baseline
    emit("V08", "PASS", "Apply dry-run changes no live resource.", initial["diff"])
    applied = cli("apply", "-c", str(PROFILE), "--confirm")
    assert applied["backup"]["status"] == "SKIP" and applied["backup"]["readiness"] == "INCOMPLETE"
    assert read_record(JOURNAL)["phase"] == "COMMITTED"
    state = read_record(ACTIVE)
    nft = resources(manifest).verify(manifest, baseline, state["nft_sha256"])
    assert not HOST.vici("--list-sas").strip()
    nft_text = command("nft", "list", "table", "ip", "ipsecvpn").stdout
    assert (
        nft_text.count("ip saddr") >= 4 and "masquerade" not in nft_text and "snat" not in nft_text
    )
    emit(
        "V04 V05 V06 V07 V09 F14",
        "PASS",
        "Two idle VICI connections and XFRM links, exact routes, dual ACL, committed state.",
        {
            "if_ids": [link.if_id for link in manifest.links],
            "nft_sha256": nft,
            "backup": "SKIP/INCOMPLETE",
        },
    )
    journal = (STATE / "journal.json").read_bytes()
    assert "NOOP" in cli("apply", "-c", str(PROFILE), "--confirm")["detail"]
    assert (STATE / "journal.json").read_bytes() == journal and read_record(ACTIVE) == state
    emit(
        "V10",
        "PASS",
        "Identical apply returns NOOP, journal and active hashes unchanged.",
        "Verified.",
    )
    saved = cli("backup", "--confirm")["backup_id"]
    assert cli("apply", "-c", str(UPDATE), "--confirm")["diff"]["add"]
    updated = current_manifest()
    resources(updated).verify(updated, baseline, read_record(ACTIVE)["nft_sha256"])
    cli("rollback", "--to", saved, "--confirm")
    resources(manifest).verify(manifest, baseline, state["nft_sha256"])
    emit(
        "V11 V12",
        "PASS",
        "Changed CIDR, Peer and if_id; verified exact rollback.",
        "Updated and original manifests each matched live state.",
    )

    for label in ("nft atomic update", "IPv4 unicast route del", "VICI load"):
        check_failure(label, manifest, baseline)
        emit(
            "V13 F11",
            "PASS",
            "Injected real command error, then verified pre-state.",
            label + " → RESTORED",
        )
    with locked():
        assert "LOCKED" in cli("apply", "-c", str(PROFILE), "--confirm", ok=False)["detail"]
    emit(
        "V15",
        "PASS",
        "Concurrent writer cannot acquire lock.",
        "LOCKED, original transaction unaffected.",
    )

    child = subprocess.run((sys.executable, __file__, "crash"), check=False)
    assert child.returncode == -signal.SIGKILL
    interrupted = read_record(JOURNAL)
    assert interrupted["phase"] == "APPLYING"
    assert "Unfinished" in cli("apply", "-c", str(PROFILE), "--confirm", ok=False)["detail"]
    cli("rollback", "--to", interrupted["id"], "--confirm")
    resources(manifest).verify(manifest, baseline, state["nft_sha256"])
    emit(
        "V14",
        "PASS",
        "SIGKILL after a real route mutation, then explicit recovery.",
        "APPLYING → STOP → RESTORED.",
    )

    bad = BACKUPS / f"{saved}.json"
    original = bad.read_bytes()
    bad.write_bytes(b"{}")
    try:
        cli("rollback", "--to", saved, "--confirm", ok=False)
        cli("rollback", "--to", "0" * 32, "--confirm", ok=False)
    finally:
        bad.write_bytes(original)
    resources(manifest).verify(manifest, baseline, state["nft_sha256"])
    emit(
        "V18", "PASS", "Corrupt/missing backups block writes.", "Both blocked; pre-state verified."
    )

    link = manifest.links[0]
    protected = link.remote_ts[0].split("/")[0]
    command("systemctl", "stop", UNIT)
    assert HOST.ip("-4", "route", "get", protected)[0]["dev"] == link.name
    command("ip", "link", "del", "dev", link.name)
    lookup = command("ip", "-4", "route", "get", protected, allowed=(2,))
    assert "Invalid argument" in lookup.stderr or "Network is unreachable" in lookup.stderr
    assert "blackhole" in command("ip", "-4", "route", "show", "exact", link.remote_ts[0]).stdout
    command("systemctl", "start", UNIT)
    boot("restore")
    resources(manifest).verify(manifest, baseline, state["nft_sha256"])
    emit(
        "F10",
        "PASS",
        "Stopped daemon and deleted XFRM; kernel lookup blocks protected CIDR.",
        "Actual blackhole selected, default WAN not returned.",
    )
    emit(
        "V20",
        "PASS",
        "Preserve baseline across install, apply, update, faults and rollback.",
        baseline,
    )
    check_secret_evidence(profile)


def check_secret_evidence(profile):
    paths = [SUMMARY, *STATE.rglob("*.json")]
    secret_values = [
        Path(link["secret_ref"][5:]).read_bytes().strip() for link in profile["site_links"]
    ]
    for path in paths:
        if path.is_file():
            content = path.read_bytes()
            assert all(
                value not in content and value.hex().encode() not in content
                for value in secret_values
            )
    assert not Path("/run/ipsecvpn/swanctl.conf").exists()
    daemon = command("journalctl", "--no-pager", "-u", UNIT, "-o", "cat").stdout.encode()
    assert all(
        value not in daemon and value.hex().encode() not in daemon for value in secret_values
    )
    emit(
        "V19",
        "PASS",
        "Scan persisted journal, snapshots and emitted evidence for both test keys.",
        "No raw or hex-encoded IKE key matches.",
    )


def after_reboot():
    ENV.update(
        HOST.probe(),
        nft=command("nft", "--version").stdout.strip(),
        strongswan=HOST.packages()["charon-systemd"],
    )
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    command("systemctl", "is-active", GUARD, RESTORE, UNIT)
    manifest = current_manifest()
    resources(manifest).verify(manifest, baseline, read_record(ACTIVE)["nft_sha256"])
    emit(
        "V17 V20",
        "PASS",
        "Independent reboot, new SSH session and automatic restore.",
        "Boot services active and protected baseline hashes identical.",
    )
    cli("uninstall", "--confirm")
    assert resources().baseline() == baseline
    assert read_record(ACTIVE) is None and HOST.packages()["charon-systemd"]
    assert not HOST.ike_ports()
    emit(
        "V16",
        "PASS",
        "Remove owned network and boot resources, keep shared packages and SSH.",
        "Exact protected baseline and package retention verified.",
    )


if __name__ == "__main__":
    action = sys.argv[1]
    if action == "crash":
        Deployment(FaultHost("IPv4 blackhole route add", crash=True)).dispatch(
            "apply", True, UPDATE
        )
    else:
        try:
            {"before-reboot": before_reboot, "after-reboot": after_reboot}[action]()
        except (AssertionError, OSError, RuntimeError, ValueError, KeyError, IndexError) as exc:
            emit("VM", "FAIL", "All executed acceptance assertions pass.", str(exc))
            raise
