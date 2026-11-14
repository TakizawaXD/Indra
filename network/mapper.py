"""
GOJO INFINITY SECURITY ∞ — NETWORK TOPOLOGY MAPPER & INVENTORY
Constructs graph representations (nodes & edges) of discovered network elements.
"""

from typing import Dict, Any, List
from backend.database import SessionLocal, Host, Port, NetworkScan
from network.diagnostics import NetworkDiagnostics

class NetworkMapper:
    """Builds visual graph representation and device inventories."""

    @classmethod
    def generate_topology_graph(cls) -> Dict[str, Any]:
        """
        Creates nodes and edges representing the network graph:
        Central Gateway -> Discovered Hosts -> Exposed Ports/Services
        """
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        overview = NetworkDiagnostics.get_device_ip_overview()
        local_ip = overview.get("primary_local_ip", "127.0.0.1")

        # Root Node: Operator Device
        nodes.append({
            "id": "node_gojo_local",
            "label": f"Gojo Operator ({local_ip})",
            "type": "operator",
            "color": "#00f0ff", # Cyan
            "size": 25
        })

        with SessionLocal() as db:
            hosts = db.query(Host).all()
            for host in hosts:
                node_id = f"host_{host.id}"
                nodes.append({
                    "id": node_id,
                    "label": f"{host.ip_address}\n{host.hostname or ''}".strip(),
                    "type": "host",
                    "status": host.status,
                    "color": "#0051ff" if host.status == "up" else "#555555", # Electric Blue
                    "size": 18
                })

                # Edge from Operator to Host
                edges.append({
                    "from": "node_gojo_local",
                    "to": node_id,
                    "label": f"{host.response_time_ms or 0}ms"
                })

                # Port nodes
                for port in host.ports:
                    port_node_id = f"port_{port.id}"
                    nodes.append({
                        "id": port_node_id,
                        "label": f"{port.port_number}/{port.service_name or 'tcp'}",
                        "type": "service",
                        "color": "#9b51e0", # Purple
                        "size": 12
                    })
                    edges.append({
                        "from": node_id,
                        "to": port_node_id,
                        "label": port.state
                    })

        return {
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges)
        }

    @classmethod
    def export_inventory(cls, format: str = "json") -> Any:
        """Exports complete network catalog."""
        with SessionLocal() as db:
            hosts = db.query(Host).all()
            inventory = [
                {
                    "ip": h.ip_address,
                    "hostname": h.hostname,
                    "status": h.status,
                    "rtt_ms": h.response_time_ms,
                    "ports": [
                        {
                            "port": p.port_number,
                            "service": p.service_name,
                            "state": p.state,
                            "banner": p.banner
                        }
                        for p in h.ports
                    ],
                    "discovered_at": h.discovered_at.isoformat()
                }
                for h in hosts
            ]
        return inventory
