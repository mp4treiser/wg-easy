import aiosqlite
import os
from typing import Optional, List
from datetime import datetime
from app.models import Peer, PeerCreate


class Database:
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Use data directory if it exists (for Docker), otherwise current directory
            data_dir = os.path.join(os.getcwd(), "data")
            if os.path.exists(data_dir) or os.path.exists("/app/data"):
                db_path = os.path.join(data_dir if os.path.exists(data_dir) else "/app/data", "wireguard.db")
            else:
                db_path = "wireguard.db"
        self.db_path = db_path
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else ".", exist_ok=True)

    async def init_db(self):
        """Initialize database and create tables"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS peers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    public_key TEXT NOT NULL UNIQUE,
                    private_key TEXT NOT NULL,
                    pre_shared_key TEXT NOT NULL,
                    ipv4_address TEXT NOT NULL UNIQUE,
                    ipv6_address TEXT,
                    allowed_ips TEXT,
                    persistent_keepalive INTEGER DEFAULT 25,
                    enabled INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS interface (
                    name TEXT PRIMARY KEY DEFAULT 'wg0',
                    private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 51820,
                    ipv4_cidr TEXT NOT NULL DEFAULT '10.8.0.0/24',
                    ipv6_cidr TEXT,
                    mtu INTEGER DEFAULT 1420,
                    endpoint TEXT,
                    dns TEXT
                )
            """)
            
            await db.commit()

    async def get_interface(self) -> Optional[dict]:
        """Get WireGuard interface configuration"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM interface WHERE name = 'wg0'") as cursor:
                row = await cursor.fetchone()
                if row:
                    return dict(row)
                return None

    async def init_interface(self, private_key: str, public_key: str, port: int = 51820,
                            ipv4_cidr: str = "10.8.0.0/24", endpoint: str = None, dns: str = None):
        """Initialize interface if it doesn't exist"""
        async with aiosqlite.connect(self.db_path) as db:
            existing = await self.get_interface()
            if not existing:
                await db.execute("""
                    INSERT INTO interface (name, private_key, public_key, port, ipv4_cidr, endpoint, dns)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, ('wg0', private_key, public_key, port, ipv4_cidr, endpoint, dns))
                await db.commit()

    async def create_peer(self, peer: PeerCreate, private_key: str, public_key: str,
                         pre_shared_key: str, ipv4_address: str, ipv6_address: Optional[str] = None) -> Peer:
        """Create a new peer"""
        async with aiosqlite.connect(self.db_path) as db_conn:
            allowed_ips_str = ",".join(peer.allowed_ips) if peer.allowed_ips else None
            cursor = await db_conn.execute("""
                INSERT INTO peers (name, public_key, private_key, pre_shared_key, 
                                 ipv4_address, ipv6_address, allowed_ips, persistent_keepalive, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            """, (
                peer.name,
                public_key,
                private_key,
                pre_shared_key,
                ipv4_address,
                ipv6_address,
                allowed_ips_str,
                peer.persistent_keepalive or 25
            ))
            await db_conn.commit()
            
            # Get the created peer
            peer_id = cursor.lastrowid
            return await self.get_peer(peer_id)

    async def get_peer(self, peer_id: int) -> Optional[Peer]:
        """Get peer by ID"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    return self._row_to_peer(dict(row))
                return None

    async def get_peer_by_public_key(self, public_key: str) -> Optional[Peer]:
        """Get peer by public key"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM peers WHERE public_key = ?", (public_key,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    return self._row_to_peer(dict(row))
                return None

    async def get_all_peers(self) -> List[Peer]:
        """Get all peers"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM peers ORDER BY created_at DESC") as cursor:
                rows = await cursor.fetchall()
                return [self._row_to_peer(dict(row)) for row in rows]

    async def delete_peer(self, peer_id: int) -> bool:
        """Delete a peer"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("DELETE FROM peers WHERE id = ?", (peer_id,))
            await db.commit()
            return cursor.rowcount > 0

    async def get_next_ipv4(self) -> str:
        """Get next available IPv4 address"""
        interface = await self.get_interface()
        if not interface:
            raise ValueError("Interface not configured")
        
        ipv4_cidr = interface['ipv4_cidr']
        base_ip = ipv4_cidr.split('/')[0]
        base_parts = base_ip.split('.')
        base_network = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}"
        
        # Get all existing IPs
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT ipv4_address FROM peers") as cursor:
                rows = await cursor.fetchall()
                existing_ips = {row[0] for row in rows}
        
        # Find next available IP (starting from .2, as .1 is usually the server)
        for i in range(2, 255):
            ip = f"{base_network}.{i}"
            if ip not in existing_ips:
                return ip
        
        raise ValueError("No available IPv4 addresses")

    def _row_to_peer(self, row: dict) -> Peer:
        """Convert database row to Peer model"""
        allowed_ips = row['allowed_ips'].split(',') if row['allowed_ips'] else []
        return Peer(
            id=row['id'],
            name=row['name'],
            public_key=row['public_key'],
            private_key=row['private_key'],
            pre_shared_key=row['pre_shared_key'],
            ipv4_address=row['ipv4_address'],
            ipv6_address=row['ipv6_address'],
            allowed_ips=allowed_ips,
            persistent_keepalive=row['persistent_keepalive'],
            enabled=bool(row['enabled']),
            created_at=datetime.fromisoformat(row['created_at']) if isinstance(row['created_at'], str) else row['created_at'],
            updated_at=datetime.fromisoformat(row['updated_at']) if isinstance(row['updated_at'], str) else row['updated_at']
        )


# Global database instance
db = Database()

