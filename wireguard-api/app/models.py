from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class PeerBase(BaseModel):
    name: str = Field(..., description="Peer name")
    ipv4_address: Optional[str] = Field(None, description="IPv4 address (auto-assigned if not provided)")
    ipv6_address: Optional[str] = Field(None, description="IPv6 address (auto-assigned if not provided)")
    allowed_ips: Optional[List[str]] = Field(None, description="Allowed IPs for the peer")
    persistent_keepalive: Optional[int] = Field(25, description="Persistent keepalive interval in seconds")


class PeerCreate(PeerBase):
    pass


class PeerMetrics(BaseModel):
    public_key: str
    endpoint: Optional[str] = None
    latest_handshake: Optional[datetime] = None
    transfer_rx: int = Field(0, description="Bytes received")
    transfer_tx: int = Field(0, description="Bytes sent")
    transfer_rx_mb: float = Field(0, description="MB received")
    transfer_tx_mb: float = Field(0, description="MB sent")


class PeerConfig(BaseModel):
    private_key: Optional[str] = None  # Only if peer was created via this API
    public_key: str
    pre_shared_key: Optional[str] = None  # Only if peer was created via this API
    ipv4_address: Optional[str] = None
    ipv6_address: Optional[str] = None
    allowed_ips: List[str]
    persistent_keepalive: Optional[int] = None
    server_public_key: str
    server_endpoint: Optional[str] = None
    server_port: int
    dns: Optional[List[str]] = None


class Peer(PeerBase):
    public_key: str
    private_key: Optional[str] = None  # Only available when peer is created via API
    pre_shared_key: Optional[str] = None  # Only available when peer is created via API
    enabled: bool = True
    metrics: Optional[PeerMetrics] = None


class PeerResponse(BaseModel):
    public_key: str
    name: Optional[str] = None
    ipv4_address: Optional[str] = None
    ipv6_address: Optional[str] = None
    allowed_ips: List[str] = []
    enabled: bool = True
    metrics: Optional[PeerMetrics] = None


class MetricsResponse(BaseModel):
    public_key: str
    peer_name: Optional[str] = None
    endpoint: Optional[str]
    latest_handshake: Optional[datetime]
    transfer_rx: int
    transfer_tx: int
    transfer_rx_mb: float
    transfer_tx_mb: float
    is_connected: bool = Field(False, description="Whether peer is currently connected")


class AllMetricsResponse(BaseModel):
    total_peers: int
    enabled_peers: int
    connected_peers: int
    peers: List[MetricsResponse]


# Store for peer keys created via API (in-memory, lost on restart)
# This is only for peers created through this API
peer_keys_store: dict = {}  # public_key -> {private_key, pre_shared_key, name}

