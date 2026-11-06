"""Exclusive durable transactions for the isolated Hub deployment."""

import os
import re
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from .host import Host
from .installer import (
    INSTALL_DIRS,
    STATE,
    activate,
    assert_files,
    deactivate,
    install_packages,
    trusted_python,
    vendor_plugins,
    verify_install_source,
)
from .profile import MAX_PROFILE_BYTES, load_profile, parse_profile
from .renderer import build_manifest, canonical, digest, external_backup, resource_diff
from .resources import Resources, link_specs, network_scope
from .secureio import Stop, make_directory, read_file, read_keys, read_record, write_record

LOCK = Path("/run/ipsecvpn.lock")
ACTIVE = STATE / "active.json"
INSTALLED = STATE / "installed.json"
RETAINED = STATE / "retained.json"
JOURNAL = STATE / "journal.json"
BACKUPS = STATE / "backups"
HISTORY = STATE / "journals"
PROFILES = Path("/etc/ipsecvpn/profiles")
TERMINAL = {"COMMITTED", "RESTORED"}


def now():
    return datetime.now(UTC).isoformat()


@contextmanager
def locked():
    import fcntl
    import stat

    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != 0
            or st.st_nlink != 1
            or stat.S_IMODE(st.st_mode) != 0o600
        ):
            raise Stop("The transaction lock file is not safely owned.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Stop("LOCKED: another deployment transaction is in progress.") from None
        yield
    finally:
        os.close(fd)


def snapshot(active):
    return build_manifest(active["profile"]) if active else None


def key_digests(keys):
    return {site: digest(key) for site, key in keys.items()}


def keys_for(active):
    keys = read_keys(active["profile"] if active else None)
    if active and active["keys"] != key_digests(keys):
        raise Stop("A referenced key no longer matches its recorded snapshot.")
    return keys


def installed_record():
    record = read_record(INSTALLED)
    if not record:
        raise Stop("Run install on a clean authorized VM before applying a profile.")
    assert_files(record)
    if record["vendor_plugins"] != vendor_plugins():
        raise Stop("Distribution strongSwan plugin configuration changed.")
    return record


def retained_install():
    current = read_record(JOURNAL)
    receipt = read_record(RETAINED)
    if receipt is None:
        # A committed uninstall from before receipts were introduced is also evidence.
        journal = current
        if (
            not journal
            or journal.get("action") != "uninstall"
            or journal.get("phase") != "COMMITTED"
        ):
            return None
    else:
        identifier = receipt.get("uninstall_id") if isinstance(receipt, dict) else None
        if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{32}", identifier):
            raise Stop("The retained-package receipt is invalid.")
        journal = (
            current
            if current and current.get("id") == identifier
            else read_record(HISTORY / f"{identifier}.json")
        )
        if (
            not journal
            or journal.get("id") != identifier
            or journal.get("action") != "uninstall"
            or journal.get("phase") != "COMMITTED"
        ):
            raise Stop("A committed uninstall does not prove the retained-package receipt.")
    return journal


def package_recovery(host, before):
    evidence = {
        "before_sha256": digest(canonical(before)) if before is not None else None,
        "after_sha256": None,
        "delta": None,
        "audit_clean": None,
    }
    try:
        after = host.package_state()
        evidence["after_sha256"] = digest(canonical(after))
        if before is not None:
            evidence["delta"] = {
                name: {"before": before.get(name), "after": after.get(name)}
                for name in sorted(before.keys() | after.keys())
                if before.get(name) != after.get(name)
            }
        evidence["audit_clean"] = not bool(host.command("Package audit", "dpkg", "--audit").strip())
    except (Stop, ValueError, OSError):
        pass
    return evidence


def read_backup(identifier):
    if not re.fullmatch(r"[0-9a-f]{32}", identifier):
        raise Stop("The backup ID is invalid.")
    record = read_record(BACKUPS / f"{identifier}.json")
    if not isinstance(record, dict) or record.get("id") != identifier or "active" not in record:
        raise Stop("The requested backup is missing or invalid.")
    return record


def read_profile(path, confirmed):
    if not confirmed:
        return load_profile(path)
    if path.parent != PROFILES or path.suffix not in {".yaml", ".yml"}:
        raise Stop("Select a root-only YAML file directly under /etc/ipsecvpn/profiles.")
    return parse_profile(read_file(path, limit=MAX_PROFILE_BYTES, parent_mode=0o700))


class Deployment:
    def __init__(self, host=None):
        self.host = host or Host()
        self.record = None

    def phase(self, phase):
        self.record["phase"] = phase
        self.record["updated_at"] = now()
        write_record(JOURNAL, self.record)
        if phase in TERMINAL | {"STOP_FOR_MANUAL"}:
            write_record(HISTORY / f"{self.record['id']}.json", self.record)

    def step(self, label, result):
        self.record["steps"].append({"time": now(), "label": label, "result": result})
        write_record(JOURNAL, self.record)

    def begin(self, action, active, target, install, baseline):
        make_directory(STATE)
        make_directory(BACKUPS)
        make_directory(HISTORY)
        identifier = uuid.uuid4().hex
        self.record = {
            "id": identifier,
            "action": action,
            "actor_uid": os.getuid(),
            "began_at": now(),
            "before": active,
            "target": target,
            "install": install,
            "baseline": baseline,
            "before_sha256": digest(canonical(active)),
            "target_sha256": digest(canonical(target)),
            "steps": [],
        }
        self.phase("PREFLIGHT_OK")
        write_record(
            BACKUPS / f"{identifier}.json",
            {
                "id": identifier,
                "active": active,
                "baseline": baseline,
                "owner": install["token"],
            },
        )
        self.phase("SNAPSHOTTED")
        self.host.step = self.step

    def recover(self):
        self.phase("RESTORING")
        self.host.step = self.step
        before = self.record["before"]
        target = self.record["target"]
        install = self.record["install"]
        try:
            if self.record["action"] == "install":
                try:
                    deactivate(self.host, install)
                finally:
                    packages = package_recovery(self.host, install.get("before_package_state"))
                    self.record["package_recovery"] = packages
                    self.record.setdefault("install_failure_packages", packages)
                self.host.assert_idle_ike()
                resources = Resources(self.host, install["token"], ())
                if resources.baseline() != self.record["baseline"]:
                    raise Stop("The install baseline differs after attempted restoration.")
                self.record["protected_baseline_unchanged"] = True
                write_record(INSTALLED, None)
                if packages["audit_clean"] is not True or packages["delta"] != {}:
                    raise Stop(
                        "The original dpkg state was not restored or could not be proven. "
                        "Compare the journal package delta and dpkg --audit, restore the "
                        "pre-install state per docs/rollback.md, then retry rollback with this ID."
                    )
                retained = install.get("retained_from")
                if not retained:
                    verify_install_source(self.host, None, self.host.package_state())
                else:
                    verify_install_source(self.host, install, self.host.package_state())
            else:
                old = snapshot(before)
                requested = snapshot(target)
                resources = Resources(self.host, install["token"], (old, requested))
                if self.record["action"] == "uninstall":
                    activate(self.host, install)
                permitted = {name for name, _ in link_specs((old, requested))}
                self.host.assert_exclusive_ike(permitted)
                current_baseline = resources.preflight(old)
                if current_baseline != self.record["baseline"]:
                    raise Stop("The protected host baseline changed; keep the transition guards.")
                resources.replace(old, keys_for(before))
                observed = resources.verify(old, self.record["baseline"])
                if before:
                    before = {**before, "nft_sha256": observed}
                write_record(ACTIVE, before)
                write_record(INSTALLED, install)
            self.phase("RESTORED")
        except (Stop, OSError, ValueError, KeyError) as exc:
            reason = str(exc) if isinstance(exc, Stop) else "protected recovery state operation"
            self.record["recovery_failure"] = reason
            self.phase("STOP_FOR_MANUAL")
            raise Stop(
                f"STOP_FOR_MANUAL: recovery could not be proven for {self.record['id']}. {reason}"
            ) from None
        finally:
            self.host.step = None

    def install(self, confirmed):
        if read_record(INSTALLED):
            installed_record()
            active = snapshot(read_record(ACTIVE))
            self.host.assert_exclusive_ike({name for name, _ in link_specs((active,))})
            return {"status": "PASS", "detail": "NOOP: owned strongSwan installation is present."}
        if read_record(ACTIVE):
            raise Stop("An active profile lacks its installation record.")
        retained = retained_install()
        before_packages = self.host.package_state()
        verify_install_source(self.host, retained["install"] if retained else None, before_packages)
        packages = retained["install"]["packages"] if retained else self.host.apt_plan()
        baseline = Resources(self.host, "preflight", ()).preflight(None)
        mode = "reinstall" if retained else "install"
        if not confirmed:
            return {
                "status": "PASS",
                "detail": f"Dry-run {mode}; no packages installed.",
                "mode": mode,
                "packages": {} if retained else packages,
            }
        install = {
            "token": uuid.uuid4().hex,
            "python": trusted_python(),
            "packages": packages,
            "before_package_state": before_packages,
            "retained_from": retained["id"] if retained else None,
            "created_dirs": [str(path) for path in INSTALL_DIRS if not path.exists()],
        }
        if retained:
            archive = HISTORY / f"{retained['id']}.json"
            if read_record(archive) is None:
                write_record(archive, retained)
            if read_record(RETAINED) is None:
                # Keep the legacy receipt available after this new journal replaces it.
                write_record(RETAINED, {"uninstall_id": retained["id"]})
        self.begin("install", None, None, install, baseline)
        try:
            self.phase("STAGED")
            self.phase("APPLYING")
            if not retained:
                install_packages(self.host, install)
            else:
                verify_install_source(self.host, retained["install"], self.host.package_state())
            activate(self.host, install)
            assert_files(install)
            self.host.assert_exclusive_ike()
            install["vendor_plugins"] = vendor_plugins()
            if retained and self.host.package_state() != before_packages:
                raise Stop("Reinstallation changed the dpkg inventory.")
            if Resources(self.host, install["token"], ()).baseline() != baseline:
                raise Stop("Installation changed a protected host baseline.")
            self.phase("VERIFIED")
            write_record(INSTALLED, install)
            self.phase("COMMITTED")
        except (Stop, OSError, ValueError, KeyError) as exc:
            reason = str(exc) if isinstance(exc, Stop) else "protected install state operation"
            self.record["failure"] = reason
            self.phase("FAILED")
            self.recover()
            raise Stop(
                "Install failed and protected state was restored. "
                f"{reason} Journal {self.record['id']}."
            ) from None
        finally:
            self.host.step = None
        return {
            "status": "PASS",
            "detail": "Reactivated the retained Ubuntu strongSwan service."
            if retained
            else "Installed the owned Ubuntu strongSwan service.",
            "mode": mode,
            "packages": {} if retained else packages,
            "journal": self.record["id"],
            "baseline_unchanged": True,
        }

    def change(self, action, profile, identifier, confirmed):
        install = installed_record()
        active = read_record(ACTIVE)
        before = snapshot(active)
        backup_state = external_backup(profile) if profile else None
        if action == "apply":
            target = build_manifest(profile)
            if before and target.event_id != before.event_id:
                raise Stop("An existing active profile cannot be silently switched.")
            requested = {"profile": profile}
        elif action == "rollback":
            saved = read_backup(identifier)
            if saved["owner"] != install["token"]:
                raise Stop("The backup belongs to a different installation.")
            requested = saved["active"]
            target = snapshot(requested)
            backup_state = external_backup(requested["profile"]) if requested else None
        else:
            requested = target = None
        resources = Resources(self.host, install["token"], (before, target))
        owned_names = {name for name, _ in link_specs((before,))}
        self.host.assert_exclusive_ike(owned_names)
        baseline = resources.preflight(target)
        resources.verify(before, baseline, active.get("nft_sha256") if active else None)
        result = {"status": "PASS", "diff": resource_diff(before, target)}
        if backup_state is not None:
            result["backup"] = backup_state
        if not confirmed:
            return {**result, "detail": "Dry-run; host resources and credentials were not changed."}

        keys_for(active)
        if action == "apply":
            keys = read_keys(profile)
            requested["keys"] = key_digests(keys)
            if active and active["profile"] == profile and active["keys"] == requested["keys"]:
                return {**result, "detail": "NOOP: the active profile and live resources match."}
        else:
            keys = keys_for(requested)

        self.begin(action, active, requested, install, baseline)
        try:
            self.phase("STAGED")
            self.phase("APPLYING")
            resources.replace(target, keys)
            observed = resources.verify(target, baseline)
            if requested:
                requested = {**requested, "nft_sha256": observed}
            write_record(ACTIVE, requested)
            if action == "uninstall":
                deactivate(self.host, install)
                if resources.baseline() != baseline:
                    raise Stop("Uninstall changed a protected host baseline.")
                write_record(RETAINED, {"uninstall_id": self.record["id"]})
                write_record(INSTALLED, None)
            self.phase("VERIFIED")
            self.phase("COMMITTED")
        except (Stop, OSError, ValueError, KeyError) as exc:
            reason = str(exc) if isinstance(exc, Stop) else "protected host state operation"
            self.record["failure"] = reason
            self.phase("FAILED")
            self.recover()
            raise Stop(
                f"{action} failed; pre-state restored. {reason} Journal {self.record['id']}."
            ) from None
        finally:
            self.host.step = None
        return {
            **result,
            "detail": "COMMITTED: project resources verified.",
            "backup_id": self.record["id"],
            "baseline_unchanged": True,
            "site_to_site": {"status": "SKIP"},
        }

    def backup(self, confirmed):
        install = installed_record()
        active = read_record(ACTIVE)
        manifest = snapshot(active)
        resources = Resources(self.host, install["token"], (manifest,))
        baseline = resources.preflight(manifest)
        self.host.assert_exclusive_ike({name for name, _ in link_specs((manifest,))})
        resources.verify(manifest, baseline, active.get("nft_sha256") if active else None)
        if not confirmed:
            return {"status": "PASS", "detail": "Dry-run; no snapshot written."}
        keys_for(active)
        identifier = uuid.uuid4().hex
        write_record(
            BACKUPS / f"{identifier}.json",
            {
                "id": identifier,
                "active": active,
                "baseline": baseline,
                "owner": install["token"],
            },
        )
        return {"status": "PASS", "detail": "Project snapshot verified.", "backup_id": identifier}

    def dispatch(self, action, confirmed, config=None, identifier=None):
        self.host.probe()
        if not confirmed:
            return self._dispatch(action, False, config, identifier)
        with locked():
            return self._dispatch(action, True, config, identifier)

    def _dispatch(self, action, confirmed, config, identifier):
        pending = read_record(JOURNAL)
        if pending and pending["phase"] not in TERMINAL:
            if action != "rollback" or identifier != pending["id"]:
                raise Stop(
                    f"Unfinished transaction; inspect and use rollback --to {pending['id']}."
                )
            if pending["phase"] != "PREFLIGHT_OK":
                read_backup(identifier)
            if not confirmed:
                return {"status": "PASS", "detail": "Dry-run; pending recovery is still blocked."}
            self.record = pending
            self.recover()
            return {"status": "PASS", "detail": "RESTORED: interrupted transaction recovered."}
        if action == "install":
            return self.install(confirmed)
        if action == "backup":
            return self.backup(confirmed)
        profile = read_profile(config, confirmed) if action == "apply" else None
        return self.change(action, profile, identifier, confirmed)


def boot(phase):
    host = Host()
    host.probe()
    with locked():
        install = read_record(INSTALLED)
        pending = read_record(JOURNAL)
        active = read_record(ACTIVE)
        interrupted = pending and pending["phase"] not in TERMINAL
        candidates = [snapshot(active)]
        if interrupted:
            candidates.extend((snapshot(pending["before"]), snapshot(pending["target"])))
            install = install or pending["install"]
        if not install or not network_scope(candidates):
            return
        resources = Resources(host, install["token"], candidates)
        if phase == "guard":
            resources.guard()
            resources.purge_runtime()
        elif interrupted:
            raise Stop(
                "An unfinished journal requires explicit rollback; boot guards remain active."
            )
        else:
            installed_record()
            target = snapshot(active)
            host.assert_exclusive_ike({name for name, _ in link_specs((target,))})
            baseline = resources.preflight(target)
            resources.replace(target, keys_for(active))
            resources.verify(target, baseline, active.get("nft_sha256") if active else None)
