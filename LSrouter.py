import json
import heapq
from collections import defaultdict
from typing import Dict, Tuple, List

from router import Router
from packet import Packet


class LSrouter(Router):
    """Nút định tuyến sử dụng giao thức Link-State (LS)."""

    def __init__(self, addr: str, heartbeat_time: int) -> None:
        super().__init__(addr)
        self.heartbeat_time: int = heartbeat_time  # khoảng thời gian gửi lại LSP
        self._last_broadcast: int = 0  # thời điểm gửi LSP gần nhất (ms)

        # Hàng xóm trực tiếp: địa chỉ → (cổng, chi phí)
        self.neighbours: Dict[str, Tuple[int, int]] = {}

        # Cơ sở dữ liệu trạng thái liên kết: router → (số thứ tự, các liên kết {hàng xóm: chi phí})
        self.lsdb: Dict[str, Tuple[int, Dict[str, int]]] = {}

        # Quản lý gói LSP cục bộ
        self._seq: int = 0  # số thứ tự LSP của chính mình
        self._update_own_lsp()  # khởi tạo LSDB với thông tin bản thân

        # Bảng chuyển tiếp: đích → cổng
        self.forward: Dict[str, int] = {}

    def _update_own_lsp(self) -> None:
        """Ghi/ghi đè gói LSP của chính router vào LSDB."""
        links = {n: cost for n, (_p, cost) in self.neighbours.items()}
        self.lsdb[self.addr] = (self._seq, links)

    def _broadcast_lsp(self, exclude_port: int | None = None) -> None:
        """Phát tán LSP hiện tại của chính mình tới tất cả hàng xóm (trừ cổng exclude_port nếu có)."""
        seq, links = self.lsdb[self.addr]
        lsp_dict = {"origin": self.addr, "seq": seq, "links": links}
        payload = json.dumps(lsp_dict)
        for nbr, (port, _cost) in self.neighbours.items():
            if exclude_port is not None and port == exclude_port:
                continue
            pkt = Packet(Packet.ROUTING, self.addr, nbr, content=payload)
            self.send(port, pkt)

    def _recompute_forwarding(self) -> None:
        """Chạy thuật toán Dijkstra để cập nhật bảng chuyển tiếp."""

        # Tạo đồ thị vô hướng từ LSDB
        graph: Dict[str, Dict[str, int]] = defaultdict(dict)
        for router, (_seq, links) in self.lsdb.items():
            for nbr, cost in links.items():
                # giữ cạnh có chi phí thấp nhất
                prev = graph[router].get(nbr)
                if prev is None or cost < prev:
                    graph[router][nbr] = cost
                    graph[nbr][router] = cost

        # Dijkstra từ chính router
        dist: Dict[str, int] = {self.addr: 0}
        prev: Dict[str, str] = {}
        pq: List[Tuple[int, str]] = [(0, self.addr)]
        while pq:
            d, u = heapq.heappop(pq)
            if d != dist.get(u):
                continue  # bỏ qua nếu lỗi thời
            for v, w in graph.get(u, {}).items():
                nd = d + w
                if nd < dist.get(v, 1 << 60):
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(pq, (nd, v))

        # Tạo bảng chuyển tiếp từ đường đi ngắn nhất
        new_fwd: Dict[str, int] = {}
        for dest in dist:
            if dest == self.addr:
                continue
            # truy ngược để tìm bước đi đầu tiên
            hop = dest
            while prev.get(hop) != self.addr:
                hop = prev[hop]
            nbr_port = self.neighbours.get(hop, (None,))[0]
            if nbr_port is not None:
                new_fwd[dest] = nbr_port
        self.forward = new_fwd

    def handle_packet(self, port: int, packet: Packet) -> None:
        """Xử lý gói tin đến từ cổng port."""
        if packet.is_traceroute:
            # Gói dữ liệu bình thường
            out_port = self.forward.get(packet.dst_addr)
            if out_port is not None:
                self.send(out_port, packet)
            return

        # Gói định tuyến: giải mã LSP
        try:
            lsp = json.loads(packet.content)
            origin: str = lsp["origin"]
            seq: int = lsp["seq"]
            links: Dict[str, int] = lsp["links"]
        except Exception:
            return  # lỗi định dạng gói

        stored_seq = self.lsdb.get(origin, (-1, {}))[0]
        if seq <= stored_seq:
            return  # gói cũ hoặc trùng lặp

        # Chấp nhận LSP mới
        self.lsdb[origin] = (seq, links)
        self._recompute_forwarding()

        # Phát tán tiếp (trừ nơi nhận)
        self._flood_received_lsp(packet, exclude_port=port)

    def _flood_received_lsp(self, pkt: Packet, exclude_port: int) -> None:
        """Chuyển tiếp gói LSP đến tất cả hàng xóm trừ một cổng."""
        for nbr, (nbr_port, _cost) in self.neighbours.items():
            if nbr_port == exclude_port:
                continue
            fwd_pkt = Packet(Packet.ROUTING, self.addr, nbr, content=pkt.content)
            self.send(nbr_port, fwd_pkt)

    def handle_new_link(self, port: int, endpoint: str, cost: int) -> None:
        """Được gọi khi có liên kết mới được thiết lập."""
        self.neighbours[endpoint] = (port, cost)
        self._seq += 1
        self._update_own_lsp()
        self._recompute_forwarding()
        self._broadcast_lsp()

    def handle_remove_link(self, port: int) -> None:
        """Được gọi khi một liên kết hiện tại bị ngắt."""
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

    def handle_time(self, time_ms: int) -> None:
        """Được simulator gọi định kỳ."""
        if time_ms >= self._last_broadcast + self.heartbeat_time:
            self._last_broadcast = time_ms
            # phát lại LSP hiện tại (nếu không thay đổi topo thì seq giữ nguyên)
            self._broadcast_lsp()

    def __repr__(self) -> str:
        """Hiển thị dạng chuỗi để debug (không dùng để chấm điểm)."""
        return f"LSrouter({self.addr}) neighbours={list(self.neighbours)}"
