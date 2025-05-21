from __future__ import annotations

"""DVrouter – Distance‑Vector routing protocol with split‑horizon/poisoned‑reverse.

Fixes & improvements over the original implementation:
• Clamps all stored/advertised costs to classic RIP infinity (16).
• Purges routes that rely on a neighbour as soon as its link disappears.
• Uses monotonic heartbeat comparison (`>= last + period`).
• Adds type hints for static analysis and readability.
"""

import json
from typing import Dict, Tuple

from router import Router
from packet import Packet


class DVrouter(Router):
    """Distance‑Vector (RIP‑like) router node."""

    INF: int = 16  # classic RIP infinity

    def __init__(self, addr: str, heartbeat_time: int) -> None:  # ms
        super().__init__(addr)  # DO NOT REMOVE
        self.heartbeat_time: int = heartbeat_time
        self.last_broadcast: int = 0  # last broadcast timestamp (ms)

        # neighbour_addr → (port, link_cost)
        self.neighbors: Dict[str, Tuple[int, int]] = {}
        # neighbour_addr → last advertised DV we received
        self.neighbor_vectors: Dict[str, Dict[str, int]] = {}
        # our own distance vector and forwarding table
        self.dv: Dict[str, int] = {addr: 0}
        self.forward: Dict[str, int] = {}

    # ------------------------------------------------------------------ utilities
    def _recompute_routes(self) -> bool:
        """One Bellman–Ford relaxation step. Returns True iff state changed."""
        INF = self.INF

        new_dv: Dict[str, int] = {self.addr: 0}
        new_fwd: Dict[str, int] = {}

        # union of all known destinations in a single pass
        dests = {self.addr}
        dests.update(self.dv)
        dests.update(self.neighbors)
        for vec in self.neighbor_vectors.values():
            dests.update(vec)

        for dest in dests:
            if dest == self.addr:
                continue

            best_cost = INF
            best_port = None
            for nbr, (port, link_cost) in self.neighbors.items():
                nbr_vec = self.neighbor_vectors.get(nbr, {})
                cost = link_cost + nbr_vec.get(dest, INF)
                if cost < best_cost:
                    best_cost = cost
                    best_port = port

            if best_cost < INF:
                new_dv[dest] = best_cost
                new_fwd[dest] = best_port

        changed = (new_dv != self.dv) or (new_fwd != self.forward)
        if changed:
            # clamp to RIP infinity before storing/advertising
            self.dv = {d: min(c, INF) for d, c in new_dv.items()}
            self.forward = new_fwd
        return changed

    def _send_vector_to_neighbor(self, nbr_addr: str, port: int) -> None:
        """Send a (poisoned) copy of our DV to a single neighbour."""
        INF = self.INF
        vec = {
            d: (INF if self.forward.get(d) == port and d != nbr_addr else c)
            for d, c in self.dv.items()
        }
        pkt = Packet(Packet.ROUTING, self.addr, nbr_addr, content=json.dumps(vec))
        self.send(port, pkt)

    def _broadcast_vector(self) -> None:
        """Send our DV to every neighbour."""
        for nbr, (port, _cost) in self.neighbors.items():
            self._send_vector_to_neighbor(nbr, port)

    # ------------------------------------------------------------------ event handlers
    def handle_packet(self, port: int, packet: Packet) -> None:  # called by simulator
        if packet.is_traceroute:
            # data packet — forward if route exists
            out_port = self.forward.get(packet.dst_addr)
            if out_port is not None:
                self.send(out_port, packet)
            return  # drop silently if no route

        # routing packet — update neighbour vector
        try:
            their_vector = json.loads(packet.content)
        except json.JSONDecodeError:
            return  # malformed packet

        # sanitize costs
        for d, c in list(their_vector.items()):
            if not isinstance(c, (int, float)) or c < 0 or c >= self.INF:
                their_vector[d] = self.INF

        nbr_addr = packet.src_addr
        nbr_info = self.neighbors.get(nbr_addr)
        if nbr_info is None or nbr_info[0] != port:
            return  # ignore packets from unknown neighbour / wrong port

        if self.neighbor_vectors.get(nbr_addr) != their_vector:
            self.neighbor_vectors[nbr_addr] = their_vector
            if self._recompute_routes():
                self._broadcast_vector()

    def handle_new_link(self, port: int, endpoint: str, cost: int) -> None:
        """A new link became available."""
        self.neighbors[endpoint] = (port, cost)
        # the neighbour obviously has a 0‑cost route to itself
        self.neighbor_vectors.setdefault(endpoint, {endpoint: 0})

        if self._recompute_routes():
            self._broadcast_vector()
        else:
            # still tell the new neighbour about our current state
            self._send_vector_to_neighbor(endpoint, port)

    def handle_remove_link(self, port: int) -> None:
        """An existing link disappeared."""
        removed_addr = None
        for nbr, (p, _c) in list(self.neighbors.items()):
            if p == port:
                removed_addr = nbr
                break
        if removed_addr is None:
            return

        # purge neighbour state
        self.neighbors.pop(removed_addr, None)
        self.neighbor_vectors.pop(removed_addr, None)

        # purge any routes that relied on that neighbour
        for dest in list(self.forward):
            if self.forward[dest] == port:
                self.dv.pop(dest, None)
                self.forward.pop(dest, None)

        if self._recompute_routes():
            self._broadcast_vector()

    def handle_time(self, time_ms: int) -> None:
        """Called periodically by simulator to allow heartbeats."""
        if time_ms >= self.last_broadcast + self.heartbeat_time:
            self.last_broadcast = time_ms
            self._broadcast_vector()

    # ------------------------------------------------------------------
    def __repr__(self) -> str:
        table = ", ".join(f"{d}:{c}" for d, c in sorted(self.dv.items()))
        return f"DVrouter({self.addr}) dv=[{table}]"
