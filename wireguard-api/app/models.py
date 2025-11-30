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
    private_key: str
    public_key: str
    pre_shared_key: str
    ipv4_address: str
    ipv6_address: Optional[str] = None
    allowed_ips: List[str]
    persistent_keepalive: int
    server_public_key: str
    server_endpoint: str
    server_port: int
    dns: Optional[List[str]] = None


class Peer(PeerBase):
    id: int
    public_key: str
    private_key: str
    pre_shared_key: str
    enabled: bool = True
    created_at: datetime
    updated_at: datetime
    metrics: Optional[PeerMetrics] = None

    class Config:
        from_attributes = True


class PeerResponse(BaseModel):
    id: int
    name: str
    public_key: str
    ipv4_address: str
    ipv6_address: Optional[str]
    enabled: bool
    created_at: datetime
    updated_at: datetime
    metrics: Optional[PeerMetrics] = None


class MetricsResponse(BaseModel):
    peer_id: int
    peer_name: str
    public_key: str
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

