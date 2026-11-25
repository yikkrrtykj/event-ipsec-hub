"""Apply and verify only declared project network and VICI objects."""

import os
import re
from pathlib import Path

from .host import SOCKET, fingerprint, route_key, rule_key, separate_nft, xfrm_id
from .renderer import (
    BLACKHOLE_METRIC,
    ROUTE_PROTOCOL,
    TABLE,
    nft_config,
    swanctl_config,
)
from .sa import Snapshot
from .secureio import (
    ObservationStop,
    Stop,
    atomic_write,
    make_directory,
    remove_file,
    sync_dir,
    trusted_dir,
)

SWANCTL_DIR = Path("/etc/swanctl")
POLICY_METRIC = "100"


def route_specs(manifests):
    result = set()
    for manifest in manifests:
        if manifest:
            for link in manifest.links:
                for cidr in link.remote_ts:
                    result.add(
                        (
                            cidr,
                            "unicast",
                            link.name,
                            str(link.route_priority),
                            ROUTE_PROTOCOL,
                            "254",
                        )
                    )
                    result.add((cidr, "blackhole", None, BLACKHOLE_METRIC, ROUTE_PROTOCOL, "254"))
    return result


def policy_rule_specs(manifests):
    return {
        (link.policy_priority, f"{link.source}/32", str(link.route_table))
        for manifest in manifests
        if manifest
        for link in manifest.links
        if link.route_table is not None
    }


def table_route_specs(manifests):
    result = {}
    for manifest in manifests:
        if manifest:
            for link in manifest.links:
                if link.route_table is not None:
                    key = (
                        "default",
                        "unicast",
                        link.wan,
                        POLICY_METRIC,
                        ROUTE_PROTOCOL,
                        str(link.route_table),
                    )
                    result[key] = link.gateway
    return result


def link_specs(manifests):
    return {
        (link.name, link.if_id) for manifest in manifests if manifest for link in manifest.links
    }


def network_scope(manifests):
    return sorted({cidr for manifest in manifests if manifest for cidr in manifest.networks})


class Resources:
    def __init__(self, host, token, candidates):
        self.host = host
        self.token = token
        self.alias = f"ipsecvpn:{token}"
        self.candidates = tuple(candidates)
        self.routes = route_specs(self.candidates)
        self.policy_rules = policy_rule_specs(self.candidates)
        self.table_routes = table_route_specs(self.candidates)
        self.links = link_specs(self.candidates)

    @property
    def runtime(self):
        return SWANCTL_DIR / f"ipsecvpn-{self.token}"

    def purge_runtime(self):
        try:
            os.close(trusted_dir(self.runtime, 0o700))
        except FileNotFoundError:
            return
        remove_file(self.runtime / "swanctl.conf")
        self.runtime.rmdir()
        sync_dir(SWANCTL_DIR)

    def network(self):
        rules, routes, links = (
            self.host.routing(permitted_rules=self.policy_rules)
            if self.policy_rules
            else self.host.routing()
        )
        owned_links = set()
        for row in links:
            name = row["ifname"]
            if row.get("ifalias") == self.alias:
                if (name, xfrm_id(row)) not in self.links:
                    raise Stop("An unregistered interface carries the project ownership tag.")
                owned_links.add(name)
            elif any(name == expected or xfrm_id(row) == if_id for expected, if_id in self.links):
                raise Stop("An XFRM name or ID belongs to an unowned interface.")
        owned_rules = {rule_key(row) for row in rules if rule_key(row) in self.policy_rules}
        owned_routes = set()
        for row in routes:
            key = route_key(row)
            if key in self.routes:
                if row.get("gateway") or row.get("nexthops") or row.get("prefsrc"):
                    raise Stop("A project-marked route has unexpected routing attributes.")
                if key[2] is not None and key[2] not in owned_links:
                    raise Stop("A project-marked route is attached to an unowned interface.")
                owned_routes.add(key)
            elif key in self.table_routes:
                if row.get("gateway") != self.table_routes[key] or row.get("nexthops"):
                    raise Stop("A project policy table route has unexpected gateway attributes.")
                owned_routes.add(key)
            elif key[4] == ROUTE_PROTOCOL:
                raise Stop("An unregistered route uses the project route protocol.")
        owned_nft, foreign_nft = separate_nft(self.host.nft())
        if owned_nft and not any(
            item.get("chain", {}).get("name") == f"owner_{self.token}" for item in owned_nft
        ):
            raise ObservationStop(
                "The private nftables table is not owned by this installation.", "NFTABLES"
            )
        return rules, routes, links, owned_routes, owned_links, owned_nft, foreign_nft, owned_rules

    def preflight(self, target):
        view = self.network()
        rules, routes, links, owned_routes, owned_links, _, foreign_nft, owned_rules = view
        self.host.check_firewall(foreign_nft)
        self.host.check_paths(target, routes, owned_routes, links, owned_links, owned_rules)
        return self.host.baseline(
            rules, routes, links, foreign_nft, owned_routes, owned_links, owned_rules
        )

    def baseline(self):
        rules, routes, links, owned_routes, owned_links, _, foreign_nft, owned_rules = (
            self.network()
        )
        return self.host.baseline(
            rules, routes, links, foreign_nft, owned_routes, owned_links, owned_rules
        )

    def nft(self, manifest, transition=False):
        owned, _ = separate_nft(self.host.nft())
        if owned and not any(
            item.get("chain", {}).get("name") == f"owner_{self.token}" for item in owned
        ):
            raise Stop("The nftables table cannot be proven owned.")
        content = f"delete table ip {TABLE}\n" if owned else ""
        if transition:
            content += nft_config(
                None,
                self.token,
                network_scope(self.candidates),
                (name for name, _ in self.links),
                handshake=manifest,
            )
        elif manifest:
            content += nft_config(manifest, self.token)
        if content:
            args = ("nft", "-f", "-")
            self.host.command("nft syntax check", "nft", "-c", "-f", "-", content=content.encode())
            self.host.command("nft atomic update", *args, content=content.encode(), mutate=True)

    def route(self, operation, spec):
        cidr, kind, interface, metric, protocol, _ = spec
        destination = ("blackhole", cidr) if kind == "blackhole" else (cidr, "dev", interface)
        self.host.command(
            f"IPv4 {kind} route {operation}",
            "ip",
            "-4",
            "route",
            operation,
            *destination,
            "table",
            "main",
            "proto",
            protocol,
            "metric",
            metric,
            mutate=True,
        )

    def table_route(self, operation, spec, gateway):
        _, _, interface, metric, protocol, table = spec
        self.host.command(
            f"IPv4 policy table route {operation}",
            "ip",
            "-4",
            "route",
            operation,
            "default",
            "via",
            gateway,
            "dev",
            interface,
            "table",
            table,
            "proto",
            protocol,
            "metric",
            metric,
            mutate=True,
        )

    def policy_rule(self, operation, spec):
        priority, source, table = spec
        self.host.command(
            f"IPv4 policy rule {operation}",
            "ip",
            "-4",
            "rule",
            operation,
            "from",
            source,
            "table",
            table,
            "priority",
            str(priority),
            mutate=True,
        )

    def guard(self, handshake=None):
        self.nft(handshake, transition=True)
        owned_routes = {spec for spec in self.network()[3] if spec in self.routes}
        for spec in sorted(spec for spec in self.routes - owned_routes if spec[1] == "blackhole"):
            self.route("add", spec)

    def load(self, manifest, keys):
        self.host.assert_exclusive_ike({name for name, _ in self.links})
        make_directory(self.runtime)
        conf = self.runtime / "swanctl.conf"
        atomic_write(conf, swanctl_config(manifest, keys).encode())
        try:
            self.host.command(
                "VICI load",
                "swanctl",
                "--load-all",
                "--clear",
                "--noprompt",
                "--file",
                str(conf),
                "--uri",
                SOCKET,
                mutate=True,
            )
        finally:
            self.purge_runtime()

    def replace(self, target, keys, *, loader=None, hold=False, handshake=None):
        # A live maintenance load may auto-start IKE (start_action=start); keep only the
        # target's outer IKE/ESP handshake open while inner traffic stays guarded.
        self.guard(handshake)
        self.host.assert_exclusive_ike({name for name, _ in self.links})
        _, _, links, routes, names, _, _, owned_rules = self.network()
        desired_links = link_specs((target,))
        desired_routes = route_specs((target,))
        desired_table_routes = table_route_specs((target,))
        desired_rules = policy_rule_specs((target,))
        for rule_spec in sorted(owned_rules - desired_rules):
            self.policy_rule("del", rule_spec)
        for t_spec in sorted((routes & set(self.table_routes)) - set(desired_table_routes)):
            self.table_route("del", t_spec, self.table_routes[t_spec])
        for spec in sorted((routes & self.routes) - desired_routes):
            if spec[1] == "unicast":
                self.route("del", spec)
        for row in links:
            name = row["ifname"]
            if name in names and (name, xfrm_id(row)) not in desired_links:
                self.host.command("XFRM delete", "ip", "link", "del", "dev", name, mutate=True)
        for name, if_id in sorted(desired_links):
            if name not in names:
                self.host.command(
                    "XFRM create",
                    "ip",
                    "link",
                    "add",
                    "name",
                    name,
                    "type",
                    "xfrm",
                    "if_id",
                    str(if_id),
                    mutate=True,
                )
                # Linux 6.8's newlink path ignores IFLA_IFALIAS on creation.
                self.host.command(
                    "XFRM mark and activate",
                    "ip",
                    "link",
                    "set",
                    "dev",
                    name,
                    "alias",
                    self.alias,
                    "up",
                    mutate=True,
                )
            else:
                self.host.command("XFRM up", "ip", "link", "set", "dev", name, "up", mutate=True)
        current_view = self.network()
        current_routes, current_rules = current_view[3], current_view[7]
        for t_spec, gateway in sorted(desired_table_routes.items()):
            if t_spec not in current_routes:
                self.table_route("add", t_spec, gateway)
        for rule_spec in sorted(desired_rules - current_rules):
            self.policy_rule("add", rule_spec)
        for spec in sorted(desired_routes - (current_routes & self.routes)):
            self.route("add", spec)
        (loader or self.load)(target, keys)
        if hold:
            self.nft(target, transition=True)
        else:
            self.finish(target)

    def finish(self, target):
        view = self.network()
        current_routes, current_rules = view[3], view[7]
        desired_routes = route_specs((target,))
        desired_table_routes = table_route_specs((target,))
        desired_rules = policy_rule_specs((target,))
        for rule_spec in sorted(current_rules - desired_rules):
            self.policy_rule("del", rule_spec)
        for t_spec in sorted((current_routes & set(self.table_routes)) - set(desired_table_routes)):
            self.table_route("del", t_spec, self.table_routes[t_spec])
        for spec in sorted((current_routes & self.routes) - desired_routes):
            self.route("del", spec)
        self.nft(target)

    def verify(self, expected, baseline, nft_sha=None, *, live=None):
        if live is not None and (not isinstance(live, Snapshot) or live.manifest != expected):
            raise Stop("The live SA proof does not belong to the expected manifest.")
        _, _, links, routes, names, table, _, owned_rules = self.network()
        wanted = {name for name, _ in link_specs((expected,))}
        up = {row["ifname"] for row in links if row["ifname"] in names and "UP" in row["flags"]}
        expected_all_routes = route_specs((expected,)) | set(table_route_specs((expected,)))
        if (
            names != wanted
            or up != wanted
            or routes != expected_all_routes
            or owned_rules != policy_rule_specs((expected,))
        ):
            raise ObservationStop(
                "Observed XFRM interfaces or exact routes differ from the manifest.", "ROUTING"
            )
        if bool(table) != bool(expected) or (nft_sha and nft_sha != fingerprint(table)):
            raise ObservationStop(
                "Observed project nftables rules differ from the expected state.", "NFTABLES"
            )
        connections = self.host.vici_connections()
        if set(connections) != wanted:
            raise ObservationStop(
                "The daemon did not report exactly the intended VICI connections.", "VICI"
            )
        if live is None:
            sas_output = self.host.vici("--list-sas").strip()
            auto_started = bool(expected) and any(
                link.start_action != "none" for link in expected.links
            )
            if sas_output:
                sa_names = {
                    line.split(":", 1)[0]
                    for line in sas_output.splitlines()
                    if line and not line[0].isspace()
                }
                if not auto_started or not sa_names.issubset(wanted):
                    raise ObservationStop(
                        "The daemon did not report exactly the intended VICI connections.", "VICI"
                    )
        for link in expected.links if expected else ():
            listing = "\n".join(connections[link.name])
            specs = link.child_specs()
            if (
                f"  local:  {link.source}" not in connections[link.name]
                or f"  remote: {link.peer}" not in connections[link.name]
                or any(
                    not re.search(rf"^  {re.escape(c_name)}: TUNNEL\b", listing, re.M)
                    for c_name, _, _ in specs
                )
            ):
                raise Stop("The loaded VICI peer addresses or CHILD differ from the manifest.")
            for direction, idx in (("local", 1), ("remote", 2)):
                observed = re.findall(rf"^    {direction}:\s+(.+)$", listing, re.M)
                expected_sets = [set(spec[idx]) for spec in specs]
                if (
                    len(observed) != len(specs)
                    or [set(row.split()) for row in observed] != expected_sets
                ):
                    raise Stop("The loaded VICI selectors differ from the authorized CIDRs.")
        inner_unicast = sorted(
            spec for spec in routes if spec in self.routes and spec[1] == "unicast"
        )
        best_by_cidr = {}
        for spec in inner_unicast:
            metric = int(spec[3])
            if spec[0] not in best_by_cidr or metric < best_by_cidr[spec[0]][0]:
                best_by_cidr[spec[0]] = (metric, spec[2])
        lookups = self.host.route_lookups((cidr.split("/")[0], None) for cidr in best_by_cidr)
        for cidr, (_, expected_dev) in best_by_cidr.items():
            lookup = lookups[cidr.split("/")[0], None]
            if len(lookup) != 1 or lookup[0].get("dev") != expected_dev:
                raise ObservationStop(
                    "The kernel did not resolve a protected network through its XFRM.",
                    "ROUTING",
                )
        policy_links = [link for link in (expected.links if expected else ()) if link.route_table]
        if policy_links:
            outer_lookups = self.host.route_lookups(
                (link.peer, link.source) for link in policy_links
            )
            for link in policy_links:
                outer = outer_lookups[link.peer, link.source]
                if (
                    len(outer) != 1
                    or outer[0].get("dev") != link.wan
                    or outer[0].get("gateway") != link.gateway
                ):
                    raise ObservationStop(
                        "Dual-ISP policy routing did not resolve peer via expected WAN gateway.",
                        "ROUTING",
                    )
        current = self.baseline()
        if current != baseline:
            changed = ", ".join(
                sorted(name for name in current if current[name] != baseline.get(name))
            )
            raise Stop(f"A protected non-project host baseline changed ({changed}).")
        return fingerprint(table) if table else None
