import json
from packet import Packet
from router import Router

class DVrouter(Router):
    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)
        self.heartbeat_time = heartbeat_time
        self.last_time = 0

        self.routing_table = {}
        self.neighbors = {}
        self.link_costs = {}
        self.dv_from_neighbors = {}
        self.last_sent = {}

        self.INFINITY = 16

    def handle_packet(self, port, packet):
        if packet.is_traceroute:
            dst = packet.dst_addr
            if dst in self.routing_table:
                next_port = self.routing_table[dst][1]
                self.send(next_port, packet)
            return
        else:
            neigh_addr = packet.src_addr
            try:
                neigh_vector = json.loads(packet.content)
            except json.JSONDecodeError:
                return

            for d, c in list(neigh_vector.items()):
                if not isinstance(c, (int, float)) or c < 0 or c >= self.INFINITY:
                    neigh_vector[d] = self.INFINITY

            if self.dv_from_neighbors.get(neigh_addr) != neigh_vector:
                self.dv_from_neighbors[neigh_addr] = neigh_vector
                self._recompute()

    def handle_new_link(self, port, endpoint, cost):
        self.neighbors[endpoint] = port
        self.link_costs[endpoint] = cost
        self.dv_from_neighbors.setdefault(endpoint, {endpoint: 0})
        self._recompute()

    def handle_remove_link(self, port):
        neighbor = None
        for nb, nb_port in self.neighbors.items():
            if nb_port == port:
                neighbor = nb
                break

        if neighbor is None:
            return

        self.neighbors.pop(neighbor, None)
        self.link_costs.pop(neighbor, None)
        self.dv_from_neighbors.pop(neighbor, None)

        for dest, (_, out_port) in list(self.routing_table.items()):
            if out_port == port:
                self.routing_table.pop(dest)

        self._recompute()

    def handle_time(self, time_ms):
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast()

    def _broadcast(self):
        for nb, nb_port in self.neighbors.items():
            vec = {}
            for dest in set(self.routing_table) | {self.addr}:
                if dest == self.addr:
                    vec[dest] = 0
                elif self.routing_table.get(dest, (self.INFINITY, None))[1] == nb_port:
                    vec[dest] = self.INFINITY  # Poisoned reverse
                else:
                    cost = self.routing_table.get(dest, (self.INFINITY,))[0]
                    vec[dest] = min(cost, self.INFINITY)

            if self.last_sent.get(nb) != vec:
                pkt = Packet(Packet.ROUTING, self.addr, nb, content=json.dumps(vec))
                self.send(nb_port, pkt)
                self.last_sent[nb] = vec

    def _recompute(self):
        updated = False
        new_table = {self.addr: (0, None)}

        all_dests = {self.addr}
        for vec in self.dv_from_neighbors.values():
            all_dests.update(vec)
        all_dests.update(self.routing_table)

        for dest in all_dests:
            if dest == self.addr:
                continue
            best_cost, best_port = self.INFINITY, None
            for nb, nb_port in self.neighbors.items():
                link_cost = self.link_costs.get(nb, self.INFINITY)
                if dest == nb:
                    cost = link_cost
                else:
                    neighbor_vec = self.dv_from_neighbors.get(nb, {})
                    cost = link_cost + neighbor_vec.get(dest, self.INFINITY)
                cost = min(cost, self.INFINITY)

                if cost < best_cost:
                    best_cost, best_port = cost, nb_port

            if best_cost < self.INFINITY:
                new_table[dest] = (best_cost, best_port)

        if new_table != self.routing_table:
            self.routing_table = new_table
            updated = True

        if updated:
            self._broadcast()

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        # TODO
        #   NOTE This method is for your own convenience and will not be graded
        return f"DVrouter(addr={self.addr})"