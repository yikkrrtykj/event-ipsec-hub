"""Verified protocol operations, separate from disk and network transactions."""

import time
from contextlib import closing

from vici.exception import CommandException

from .renderer import build_manifest, connection_settings
from .resources import Resources
from .sa import SAError, identity, inventory, session
from .secureio import ObservationStop, Stop


def assert_baseline(active, baseline):
    if active and active.get("host_baseline", baseline) != baseline:
        changed = {
            key for key, value in active["host_baseline"].items() if baseline.get(key) != value
        }
        stage = {
            "foreign_nft": "NFTABLES",
            "ssh": "SSH_BASELINE",
            "default_routes": "ROUTING",
            "foreign_routes": "ROUTING",
            "sysctl": "SYSCTL_BASELINE",
        }.get(next(iter(changed)) if len(changed) == 1 else "", "HOST_BASELINE")
        raise ObservationStop(
            "The recorded SSH, routing or foreign firewall baseline has changed.", stage
        )


def owned_resources(host, install, active):
    manifest = build_manifest(active["profile"]) if active else None
    resources = Resources(host, install["token"], (manifest,))
    pid = host.assert_daemon({link.name for link in manifest.links} if manifest else set())
    baseline = resources.preflight(manifest)
    assert_baseline(active, baseline)
    observed = inventory(host, manifest, pid)
    resources.verify(
        manifest, baseline, active.get("nft_sha256") if active else None, live=observed
    )
    return manifest, observed, pid


AUTOSTART_WAIT_SECONDS = 15.0


def await_autostart(host, manifest, pid, link, timeout=AUTOSTART_WAIT_SECONDS, interval=0.5):
    """Wait for a start_action=start load to finish before any explicit initiate."""
    deadline = time.monotonic() + timeout
    partial = None
    last = None
    while True:
        try:
            already = inventory(host, manifest, pid, attempts=1).get(link.name)
            if already and already.child:
                return already, None
            partial = already
            last = None
        except SAError as exc:
            if exc.reason == "UNOWNED_DAEMON":
                raise
            last = exc
        if time.monotonic() >= deadline:
            return partial, last
        time.sleep(interval)


def initiate_link(host, manifest, pid, link):
    installed = set()
    if link.start_action == "start":
        already, last = await_autostart(host, manifest, pid, link)
        if already and already.child:
            return already
        if last is not None and last.reason == "UNOWNED_SA":
            raise last
        if already:
            installed = set(already.child_map())
    elif len(link.child_specs()) > 1:
        existing = inventory(host, manifest, pid).get(link.name)
        if existing:
            installed = set(existing.child_map())
    diagnostic = "IKE_NEGOTIATION_UNVERIFIED"
    with session(pid) as client:
        verify_initiate_config(client, manifest)
        try:
            for child_name, _, _ in link.child_specs():
                if child_name in installed:
                    continue
                for event in client.initiate(
                    {"ike": link.name, "child": child_name, "timeout": "6000", "loglevel": "1"}
                ):
                    msg = event.get("msg", b"").lower()
                    if b"ts_unacceptable" in msg or b"traffic selectors unacceptable" in msg:
                        diagnostic = "CHILD_SELECTORS"
                    elif b"authentication_failed" in msg or b"no shared key" in msg:
                        diagnostic = "IKE_AUTHENTICATION"
                    elif b"no_proposal_chosen" in msg or b"no proposal found" in msg:
                        diagnostic = "PROPOSAL_REJECTED"
                    elif diagnostic == "IKE_NEGOTIATION_UNVERIFIED" and b"retransmit" in msg:
                        diagnostic = "PEER_UNREACHABLE"
        except CommandException:
            raise SAError(
                diagnostic, "The targeted IKE/CHILD negotiation did not complete."
            ) from None
    observed = inventory(host, manifest, pid).get(link.name)
    if not observed or not observed.child:
        raise SAError("CHILD_NOT_ESTABLISHED", "The target did not install a verified CHILD SA.")
    return observed


def verify_initiate_config(client, manifest):
    links = {item.name: item for item in manifest.links} if manifest else {}
    seen = set()
    for event in client.list_conns():
        for name, row in event.items():
            if name in seen or name not in links:
                raise Stop("The daemon has an unowned loaded connection.")
            seen.add(name)
            link = links[name]
            auth = {key for key in row if key.startswith(("local-", "remote-"))}
            if auth != {"local-1", "remote-1"} or row.get("version") != b"IKEv2":
                raise Stop("The loaded authentication profile is not the expected IKEv2 PSK.")
            for direction, expected in (("local", link.local_id), ("remote", link.remote_id)):
                section = row[f"{direction}-1"]
                if section.get("class") != b"pre-shared key" or identity(
                    section.get("id", b"").decode("ascii")
                ) != identity(expected):
                    raise Stop("A loaded IKE identity differs from the active manifest.")
    keys = set(client.get_shared().get("keys", ()))
    if (
        seen != set(links)
        or keys != {f"ike-{name}".encode() for name in links}
        or client.get_keys().get("keys")
    ):
        raise Stop("The loaded credential or connection inventory is not project-exclusive.")


def rekey_ids(event, kind, link, expected_old=None):
    item = event.get(link.name, {})
    if kind == "child":
        children = item.get("child-sas", {})
        if expected_old is not None:
            for candidate in children.values():
                try:
                    if int(candidate["old"]["uniqueid"]) == expected_old:
                        item = candidate
                        break
                except (KeyError, ValueError, TypeError):
                    continue
            else:
                item = {}
        else:
            item = next(iter(children.values()), {}) if len(children) == 1 else {}
    try:
        return int(item["old"]["uniqueid"]), int(item["new"]["uniqueid"])
    except (KeyError, ValueError, TypeError):
        return None


def _rekey_single(pid, link, kind, previous):
    with (
        session(pid) as watcher,
        closing(watcher.listen([f"{kind}-rekey"], timeout=0.15)) as events,
    ):
        next(events)  # The first iteration registers before the command on the second socket.
        with session(pid) as client:
            reply = client.request("rekey", {f"{kind}-id": str(previous)})
            if reply.get("matches") != b"1":
                raise SAError("SA_TRANSITION", "The verified rekey target changed before dispatch.")
        deadline = time.monotonic() + 7
        relation = None
        for _, event in events:
            relation = (
                rekey_ids(event, kind, link, expected_old=previous if kind == "child" else None)
                if event
                else None
            )
            if relation and relation[0] == previous and relation[1] != previous:
                break
            if time.monotonic() >= deadline:
                raise SAError(
                    "SA_TRANSITION", "The daemon did not confirm the old/new SA relation."
                )
        if relation is None or relation[0] != previous or relation[1] == previous:
            raise SAError("SA_TRANSITION", "The daemon did not confirm the old/new SA relation.")
    return relation


def rekey_link(host, manifest, pid, link, old, kind):
    old_children = getattr(old, "children", ())
    if kind == "child" and len(old_children) > 1:
        expected_new = {}
        for c_name, c_obj in old_children:
            relation = _rekey_single(pid, link, "child", c_obj.unique_id)
            expected_new[c_name] = relation[1]
        current = inventory(host, manifest, pid, attempts=10, delay=0.7).get(link.name)
        if not current or not current.child:
            raise SAError("SA_TRANSITION", "No stable CHILD was observed after rekey.")
        cmap = current.child_map()
        if any(
            cmap.get(c_name, None) is None or cmap[c_name].unique_id != new_id
            for c_name, new_id in expected_new.items()
        ):
            raise SAError("SA_TRANSITION", "The new SA did not match the daemon's rekey event.")
        return current

    previous = old.child.unique_id if kind == "child" else old.unique_id
    relation = _rekey_single(pid, link, kind, previous)
    current = inventory(host, manifest, pid, attempts=10, delay=0.7).get(link.name)
    if not current or not current.child:
        raise SAError("SA_TRANSITION", "No stable CHILD was observed after rekey.")
    observed = current.child.unique_id if kind == "child" else current.unique_id
    if observed != relation[1]:
        raise SAError("SA_TRANSITION", "The new SA did not match the daemon's rekey event.")
    return current


def drain_links(host, manifest, pid, live, *, max_rechecks=2):
    rechecks = 0
    reverified = []
    expected_names = {ike.name for ike in live.ikes}
    current = inventory(host, manifest, pid)
    if current != live:
        if {ike.name for ike in current.ikes} != expected_names or rechecks >= max_rechecks:
            raise SAError("SA_TRANSITION", "The active SAs changed after the maintenance snapshot.")
        rechecks += 1
        reverified.append(
            {
                "phase": "pre_drain",
                "before_ids": {ike.name: ike.unique_id for ike in live.ikes},
                "after_ids": {ike.name: ike.unique_id for ike in current.ikes},
            }
        )
    remaining_names = [ike.name for ike in current.ikes]
    while remaining_names:
        name = remaining_names[0]
        ike = current.get(name)
        if ike is None:
            raise SAError("SA_TRANSITION", "An expected owned SA disappeared before termination.")
        dispatched = False
        while not dispatched:
            try:
                with session(pid) as client:
                    reply = client.request(
                        "terminate",
                        {
                            "ike-id": str(ike.unique_id),
                            "force": "yes",
                            "timeout": "2500",
                            "loglevel": "0",
                        },
                    )
                    if reply.get("matches") != b"1":
                        refreshed = inventory(host, manifest, pid)
                        if {item.name for item in refreshed.ikes} != set(
                            remaining_names
                        ) or rechecks >= max_rechecks:
                            raise SAError(
                                "SA_TRANSITION", "The verified termination target changed."
                            )
                        rechecks += 1
                        new_ike = refreshed.get(name)
                        reverified.append(
                            {
                                "phase": "mid_drain_target",
                                "connection": name,
                                "before_id": ike.unique_id,
                                "after_id": new_ike.unique_id,
                            }
                        )
                        current = refreshed
                        ike = new_ike
                        continue
                    dispatched = True
            except SAError as exc:
                if exc.reason != "VICI_REJECTED":
                    raise
                dispatched = True
        remaining_names.pop(0)
        observed = inventory(host, manifest, pid, attempts=8, delay=0.55)
        expected_remaining = tuple(current.get(rem) for rem in remaining_names)
        if observed.ikes != expected_remaining:
            if {item.name for item in observed.ikes} == set(
                remaining_names
            ) and rechecks < max_rechecks:
                rechecks += 1
                reverified.append(
                    {
                        "phase": "mid_drain_sibling",
                        "remaining": list(remaining_names),
                        "after_ids": {item.name: item.unique_id for item in observed.ikes},
                    }
                )
            else:
                raise SAError("SA_TRANSITION", "The precise set of owned SAs did not drain.")
        current = observed
    return reverified


def _clear_connecting_sa(pid, name):
    """Remove any half-open non-ESTABLISHED IKE SA for a target connection after timeout."""
    try:
        with session(pid) as client:
            for event in client.list_sas():
                row = event.get(name)
                if row and row.get("state") != b"ESTABLISHED" and "uniqueid" in row:
                    try:
                        uid = int(row["uniqueid"])
                    except (ValueError, TypeError):
                        continue
                    client.request(
                        "terminate", {"ike-id": str(uid), "force": "yes", "timeout": "2500"}
                    )
    except SAError as exc:
        if exc.reason == "UNOWNED_DAEMON":
            raise


def reconnect_owned(host, install, active, *, site=None, max_attempts=3, base_delay=0.4):
    """Bounded per-site reconnect that preserves healthy sibling SAs."""
    manifest, live, pid = owned_resources(host, install, active)
    if not manifest:
        return {"status": "SKIP", "detail": "No active profile is deployed.", "links": []}
    targets = [
        link
        for link in manifest.links
        if site is None or link.site_id == site or link.key_id == site
    ]
    if site is not None and not targets:
        raise Stop("Select a site or link in the current active profile.")
    outcomes = []
    exhausted = False
    for link in targets:
        existing = live.get(link.name)
        if existing and existing.child:
            outcomes.append(
                {
                    "site_id": link.site_id,
                    "link_id": link.key_id,
                    "action": "NOOP_HEALTHY",
                    "ike_id": existing.unique_id,
                    "child_id": existing.child.unique_id,
                }
            )
            continue
        last_reason = "UNVERIFIED_SA"
        connected = None
        for attempt in range(1, max(1, int(max_attempts)) + 1):
            try:
                connected = initiate_link(host, manifest, pid, link)
                outcomes.append(
                    {
                        "site_id": link.site_id,
                        "link_id": link.key_id,
                        "action": "RECONNECTED",
                        "attempts": attempt,
                        "ike_id": connected.unique_id,
                        "child_id": connected.child.unique_id,
                    }
                )
                break
            except SAError as exc:
                last_reason = exc.reason
                if exc.reason in {"UNOWNED_SA", "UNOWNED_DAEMON"}:
                    raise
                _clear_connecting_sa(pid, link.name)
                if attempt < max_attempts:
                    time.sleep(base_delay * (2 ** (attempt - 1)))
        if connected is None:
            exhausted = True
            outcomes.append(
                {
                    "site_id": link.site_id,
                    "link_id": link.key_id,
                    "action": "RECONNECT_EXHAUSTED",
                    "attempts": max_attempts,
                    "reason_code": last_reason,
                }
            )
    return {
        "status": "FAIL" if exhausted else "PASS",
        "detail": (
            "One or more links exhausted bounded reconnect attempts."
            if exhausted
            else "Owned links verified or reconnected."
        ),
        "links": outcomes,
    }


def configure_scoped(host, pid, candidates, target, keys):
    known = {link.name for model in candidates if model for link in model.links}
    desired = {link.name: link for link in target.links} if target else {}
    host.assert_exclusive_ike(known)
    with session(pid) as client:
        conns = {name.decode("ascii") for name in client.get_conns().get("conns", ())}
        shared = {name.decode("ascii") for name in client.get_shared().get("keys", ())}
        if not conns.issubset(known) or not shared.issubset({f"ike-{name}" for name in known}):
            raise Stop("A non-project connection or shared credential is loaded.")
        if client.get_keys().get("keys"):
            raise Stop("The daemon has an unowned private credential.")
        # All active SAs were drained above; unload existing project conns before loading desired
        # conns so removed children are cleared and start_action=start fires uniformly.
        for name in sorted(conns):
            client.request("unload-conn", {"name": name})
        for key in sorted(shared - {f"ike-{name}" for name in desired}):
            client.request("unload-shared", {"id": key})
        for name, link in desired.items():
            client.request(
                "load-shared",
                {
                    "id": f"ike-{name}",
                    "type": "IKE",
                    "data": keys[link.key_id],
                    "owners": [link.local_id, link.remote_id],
                },
            )
            client.request("load-conn", {name: connection_settings(link)})
