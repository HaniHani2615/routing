from __future__ import annotations

"""LSrouter – Link-State routing protocol implementation (simple OSPF-like).

Key features
============
* Floods link-state packets (LSPs) carrying *only this router's* adjacency list.
* Each LSP is tagged with a monotonically increasing **sequence number** so
  duplicates/old updates are discarded.
* A lightweight **Dijkstra** implementation recomputes the forwarding table
  whenever the LS database changes.
* Periodic heart-beat floods repeat the *latest* LSP every ``heartbeat_time``
  milliseconds (same sequence number if topology hasn't changed).
* No external libraries – just ``heapq`` from the standard library.

This file respects the project restrictions: it only touches Packet, Router
and built-ins.
"""

import json
import heapq
from collections import defaultdict
from typing import Dict, Tuple, List

from router import Router
from packet import Packet


class LSrouter(Router):
    """Link-State (LS) routing protocol router node."""

    def __init__(self, addr: str, heartbeat_time: int) -> None:
        super().__init__(addr)  # DO NOT REMOVE
        self.heartbeat_time: int = heartbeat_time
        self._last_broadcast: int = 0  # last LSP send (ms)

        # ------------- neighbour & topo state -------------
        # Direct neighbours:  nbr_addr → (port, cost)
        self.neighbours: Dict[str, Tuple[int, int]] = {}

        # Link-state database:  router_addr → (seq, links {nbr: cost})
        self.lsdb: Dict[str, Tuple[int, Dict[str, int]]] = {}

        # Local LSP bookkeeping
        self._seq: int = 0  # own sequence number
        self._update_own_lsp()  # seed LSDB with ourselves

        # Forwarding table:   dest_addr → port
        self.forward: Dict[str, int] = {}

    # ==================================================================
    # Internal helpers
    # ------------------------------------------------------------------
    def _update_own_lsp(self) -> None:
        """Write / overwrite our LSP in the LSDB."""
        links = {n: cost for n, (_p, cost) in self.neighbours.items()}
        self.lsdb[self.addr] = (self._seq, links)

    # ..................................................................
    def _broadcast_lsp(self, exclude_port: int | None = None) -> None:
        """Flood *our* current LSP to every neighbour (except *exclude_port*)."""
        seq, links = self.lsdb[self.addr]
        lsp_dict = {"origin": self.addr, "seq": seq, "links": links}
        payload = json.dumps(lsp_dict)
        for nbr, (port, _cost) in self.neighbours.items():
            if exclude_port is not None and port == exclude_port:
                continue
            pkt = Packet(Packet.ROUTING, self.addr, nbr, content=payload)
            self.send(port, pkt)

    # ..................................................................
    def _recompute_forwarding(self) -> None:
        """Run Dijkstra, rebuild *self.forward* in-place."""
        # Build undirected graph from LSDB
        graph: Dict[str, Dict[str, int]] = defaultdict(dict)
        for router, (_seq, links) in self.lsdb.items():
            for nbr, cost in links.items():
                # keep the cheapest edge seen so far
                prev = graph[router].get(nbr)
                if prev is None or cost < prev:
                    graph[router][nbr] = cost
                    graph[nbr][router] = cost  # undirected

        # Dijkstra from self.addr
        dist: Dict[str, int] = {self.addr: 0}
        prev: Dict[str, str] = {}
        pq: List[Tuple[int, str]] = [(0, self.addr)]
        while pq:
            d, u = heapq.heappop(pq)
            if d != dist.get(u):
                continue  # stale
            for v, w in graph.get(u, {}).items():
                nd = d + w
                if nd < dist.get(v, 1 << 60):
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(pq, (nd, v))

        # Build forwarding table
        new_fwd: Dict[str, int] = {}
        for dest in dist:
            if dest == self.addr:
                continue
            # trace back to find first hop after self.addr
            hop = dest
            while prev.get(hop) != self.addr:
                hop = prev[hop]
            nbr_port = self.neighbours.get(hop, (None,))[0]
            if nbr_port is not None:
                new_fwd[dest] = nbr_port
        self.forward = new_fwd

    # ==================================================================
    # Event handlers invoked by the simulator
    # ------------------------------------------------------------------
    def handle_packet(self, port: int, packet: Packet) -> None:
        """Process incoming packet from *port*."""
        if packet.is_traceroute:
            # Normal data packet
            out_port = self.forward.get(packet.dst_addr)
            if out_port is not None:
                self.send(out_port, packet)
            return

        # ---------------- routing packet (LSP) ----------------
        try:
            lsp = json.loads(packet.content)
            origin: str = lsp["origin"]
            seq: int = lsp["seq"]
            links: Dict[str, int] = lsp["links"]
        except Exception:
            return  # malformed

        stored_seq = self.lsdb.get(origin, (-1, {}))[0]
        if seq <= stored_seq:
            return  # old or duplicate LSP

        # Accept the LSP
        self.lsdb[origin] = (seq, links)
        self._recompute_forwarding()

        # Flood further (except to where it came from)
        self._flood_received_lsp(packet, exclude_port=port)

    # ..........................
    def _flood_received_lsp(self, pkt: Packet, exclude_port: int) -> None:
        """Forward *pkt* (already JSON-encoded) to all neighbours except one."""
        for nbr, (nbr_port, _cost) in self.neighbours.items():
            if nbr_port == exclude_port:
                continue
            fwd_pkt = Packet(Packet.ROUTING, self.addr, nbr, content=pkt.content)
            self.send(nbr_port, fwd_pkt)

    # ------------------------------------------------------------------
    def handle_new_link(self, port: int, endpoint: str, cost: int) -> None:
        """Called when a new link becomes active."""
        self.neighbours[endpoint] = (port, cost)
        self._seq += 1
        self._update_own_lsp()
        self._recompute_forwarding()
        self._broadcast_lsp()

    # ..................................................................
    def handle_remove_link(self, port: int) -> None:
        """Called when an existing link goes down."""
        dead_nbr = None
        for nbr, (p, _c) in list(self.neighbours.items()):
            if p == port:
                dead_nbr = nbr
                break
        if dead_nbr is None:
            return
        self.neighbours.pop(dead_nbr, None)

        self._seq += 1
        self._update_own_lsp()
        self._recompute_forwarding()
        self._broadcast_lsp()

    # ------------------------------------------------------------------
    def handle_time(self, time_ms: int) -> None:
        """Periodic timer provided by simulator."""
        if time_ms >= self._last_broadcast + self.heartbeat_time:
            self._last_broadcast = time_ms
            # rebroadcast *latest* LSP (seq unchanged if no topo change)
            self._broadcast_lsp()

    # ==================================================================
    def __repr__(self) -> str:
        """Debug-friendly representation (not graded)."""
        return f"LSrouter({self.addr}) neighbours={list(self.neighbours)}"
