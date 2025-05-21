import json
from typing import Dict, Tuple

from router import Router
from packet import Packet


class DVrouter(Router):
    """Distance‑Vector (RIP‑like) router node."""

    INF: int = 16

    def __init__(self, addr: str, heartbeat_time: int) -> None:  # Khởi tạo địa chỉ và thời gian heartbeat
        super().__init__(addr)
        self.heartbeat_time: int = heartbeat_time  # Chu kỳ gửi thông tin định tuyến
        self.last_broadcast: int = 0  # Thời điểm gửi DV lần cuối

        # Địa chỉ hàng xóm → (cổng kết nối, chi phí liên kết)
        self.neighbors: Dict[str, Tuple[int, int]] = {}
        # Địa chỉ hàng xóm → Bảng định tuyến DV cuối cùng nhận được
        self.neighbor_vectors: Dict[str, Dict[str, int]] = {}
        # Bảng định tuyến DV hiện tại và bảng chuyển tiếp
        self.dv: Dict[str, int] = {addr: 0}
        self.forward: Dict[str, int] = {}

    def _recompute_routes(self) -> bool:
        """Một bước lặp Bellman–Ford. Trả về True nếu có thay đổi."""
        INF = self.INF

        new_dv: Dict[str, int] = {self.addr: 0}
        new_fwd: Dict[str, int] = {}

        # Tập hợp tất cả đích đến đã biết
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
            # Giới hạn chi phí tối đa trước khi lưu/gửi
            self.dv = {d: min(c, INF) for d, c in new_dv.items()}
            self.forward = new_fwd
        return changed

    def _send_vector_to_neighbor(self, nbr_addr: str, port: int) -> None:
        """Gửi bản sao bảng DV (có thể bị 'đầu độc') đến 1 hàng xóm."""
        INF = self.INF
        vec = {
            d: (INF if self.forward.get(d) == port and d != nbr_addr else c)
            for d, c in self.dv.items()
        }
        pkt = Packet(Packet.ROUTING, self.addr, nbr_addr, content=json.dumps(vec))
        self.send(port, pkt)

    def _broadcast_vector(self) -> None:
        """Gửi bảng DV đến tất cả các hàng xóm."""
        for nbr, (port, _cost) in self.neighbors.items():
            self._send_vector_to_neighbor(nbr, port)

    def handle_packet(self, port: int, packet: Packet) -> None:
        # Gói dữ liệu truy vết — chuyển tiếp nếu có đường đi
        if packet.is_traceroute:
            out_port = self.forward.get(packet.dst_addr)
            if out_port is not None:
                self.send(out_port, packet)
            return  # bỏ qua nếu không có đường

        # Gói định tuyến — cập nhật bảng vector của hàng xóm
        try:
            their_vector = json.loads(packet.content)
        except json.JSONDecodeError:
            return  # gói tin lỗi

        # Lọc các giá trị chi phí không hợp lệ
        for d, c in list(their_vector.items()):
            if not isinstance(c, (int, float)) or c < 0 or c >= self.INF:
                their_vector[d] = self.INF

        nbr_addr = packet.src_addr
        nbr_info = self.neighbors.get(nbr_addr)
        if nbr_info is None or nbr_info[0] != port:
            return  # bỏ qua nếu từ hàng xóm không hợp lệ

        # Cập nhật nếu có sự thay đổi trong DV của hàng xóm
        if self.neighbor_vectors.get(nbr_addr) != their_vector:
            self.neighbor_vectors[nbr_addr] = their_vector
            if self._recompute_routes():
                self._broadcast_vector()

    def handle_new_link(self, port: int, endpoint: str, cost: int) -> None:
        """Khi một liên kết mới được thêm vào."""
        self.neighbors[endpoint] = (port, cost)
        self.neighbor_vectors.setdefault(endpoint, {endpoint: 0})

        if self._recompute_routes():
            self._broadcast_vector()
        else:
            self._send_vector_to_neighbor(endpoint, port)

    def handle_remove_link(self, port: int) -> None:
        """Khi một liên kết hiện tại bị ngắt."""
        removed_addr = None
        for nbr, (p, _c) in list(self.neighbors.items()):
            if p == port:
                removed_addr = nbr
                break
        if removed_addr is None:
            return

        # Xoá trạng thái của hàng xóm bị ngắt
        self.neighbors.pop(removed_addr, None)
        self.neighbor_vectors.pop(removed_addr, None)

        # Xoá các đường đi phụ thuộc vào hàng xóm này
        for dest in list(self.forward):
            if self.forward[dest] == port:
                self.dv.pop(dest, None)
                self.forward.pop(dest, None)

        if self._recompute_routes():
            self._broadcast_vector()

    def handle_time(self, time_ms: int) -> None:
        """Hàm được gọi định kỳ để xử lý heartbeat."""
        if time_ms >= self.last_broadcast + self.heartbeat_time:
            self.last_broadcast = time_ms
            self._broadcast_vector()

    def __repr__(self) -> str:
        table = ", ".join(f"{d}:{c}" for d, c in sorted(self.dv.items()))
        return f"DVrouter({self.addr}) dv=[{table}]"
