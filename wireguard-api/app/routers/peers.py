from fastapi import APIRouter, HTTPException, status, Response
from typing import List
from app.models import PeerCreate, PeerResponse, PeerConfig
from app.database import db
from app.utils.wireguard import WireGuardManager

router = APIRouter()
wg = WireGuardManager()


@router.post("/", response_model=PeerResponse, status_code=status.HTTP_201_CREATED)
async def create_peer(peer: PeerCreate):
    """Create a new WireGuard peer"""
    try:
        # Generate keys
        private_key = wg.generate_private_key()
        public_key = wg.get_public_key(private_key)
        pre_shared_key = wg.generate_pre_shared_key()
        
        # Get or assign IP address
        if peer.ipv4_address:
            ipv4_address = peer.ipv4_address
        else:
            ipv4_address = await db.get_next_ipv4()
        
        # Create peer in database
        created_peer = await db.create_peer(
            peer=peer,
            private_key=private_key,
            public_key=public_key,
            pre_shared_key=pre_shared_key,
            ipv4_address=ipv4_address,
            ipv6_address=peer.ipv6_address
        )
        
        # Update WireGuard configuration
        await update_wireguard_config()
        
        # Get metrics if available
        metrics = wg.get_peer_metrics(public_key)
        
        return PeerResponse(
            id=created_peer.id,
            name=created_peer.name,
            public_key=created_peer.public_key,
            ipv4_address=created_peer.ipv4_address,
            ipv6_address=created_peer.ipv6_address,
            enabled=created_peer.enabled,
            created_at=created_peer.created_at,
            updated_at=created_peer.updated_at,
            metrics=metrics
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create peer: {str(e)}"
        )


@router.get("/", response_model=List[PeerResponse])
async def list_peers():
    """Get all peers"""
    try:
        peers = await db.get_all_peers()
        result = []
        
        for peer in peers:
            metrics = wg.get_peer_metrics(peer.public_key)
            result.append(PeerResponse(
                id=peer.id,
                name=peer.name,
                public_key=peer.public_key,
                ipv4_address=peer.ipv4_address,
                ipv6_address=peer.ipv6_address,
                enabled=peer.enabled,
                created_at=peer.created_at,
                updated_at=peer.updated_at,
                metrics=metrics
            ))
        
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list peers: {str(e)}"
        )


@router.get("/{peer_id}", response_model=PeerResponse)
async def get_peer(peer_id: int):
    """Get peer by ID"""
    peer = await db.get_peer(peer_id)
    if not peer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Peer {peer_id} not found"
        )
    
    metrics = wg.get_peer_metrics(peer.public_key)
    
    return PeerResponse(
        id=peer.id,
        name=peer.name,
        public_key=peer.public_key,
        ipv4_address=peer.ipv4_address,
        ipv6_address=peer.ipv6_address,
        enabled=peer.enabled,
        created_at=peer.created_at,
        updated_at=peer.updated_at,
        metrics=metrics
    )


@router.delete("/{peer_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_peer(peer_id: int):
    """Delete a peer"""
    peer = await db.get_peer(peer_id)
    if not peer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Peer {peer_id} not found"
        )
    
    deleted = await db.delete_peer(peer_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete peer"
        )
    
    # Update WireGuard configuration
    await update_wireguard_config()
    
    return None


@router.get("/{peer_id}/config", response_model=PeerConfig)
async def get_peer_config(peer_id: int):
    """Get peer configuration (keys and config parameters)"""
    peer = await db.get_peer(peer_id)
    if not peer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Peer {peer_id} not found"
        )
    
    interface = await db.get_interface()
    if not interface:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="WireGuard interface not configured"
        )
    
    allowed_ips = peer.allowed_ips if peer.allowed_ips else ['0.0.0.0/0']
    dns = None
    if interface.get('dns'):
        dns = interface['dns'].split(',') if isinstance(interface['dns'], str) else interface['dns']
    
    return PeerConfig(
        private_key=peer.private_key,
        public_key=peer.public_key,
        pre_shared_key=peer.pre_shared_key,
        ipv4_address=peer.ipv4_address,
        ipv6_address=peer.ipv6_address,
        allowed_ips=allowed_ips,
        persistent_keepalive=peer.persistent_keepalive,
        server_public_key=interface['public_key'],
        server_endpoint=interface.get('endpoint', ''),
        server_port=interface.get('port', 51820),
        dns=dns
    )


@router.get("/{peer_id}/config/text", response_class=Response)
async def get_peer_config_text(peer_id: int):
    """Get peer configuration as text (WireGuard config format)"""
    peer = await db.get_peer(peer_id)
    if not peer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Peer {peer_id} not found"
        )
    
    interface = await db.get_interface()
    if not interface:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="WireGuard interface not configured"
        )
    
    peer_dict = {
        'private_key': peer.private_key,
        'ipv4_address': peer.ipv4_address,
        'ipv6_address': peer.ipv6_address,
        'allowed_ips': peer.allowed_ips if peer.allowed_ips else ['0.0.0.0/0'],
        'pre_shared_key': peer.pre_shared_key,
        'persistent_keepalive': peer.persistent_keepalive
    }
    
    config_text = wg.generate_client_config(peer_dict, interface)
    
    return Response(
        content=config_text,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="wg-{peer.name}.conf"'
        }
    )


async def update_wireguard_config():
    """Update WireGuard configuration file and sync"""
    try:
        interface = await db.get_interface()
        if not interface:
            raise Exception("Interface not configured")
        
        peers = await db.get_all_peers()
        enabled_peers = [p for p in peers if p.enabled]
        
        # Generate interface section
        config_lines = [
            "[Interface]",
            f"PrivateKey = {interface['private_key']}",
            f"Address = {interface['ipv4_cidr'].split('/')[0].rsplit('.', 1)[0]}.1/{interface['ipv4_cidr'].split('/')[1]}",
            f"ListenPort = {interface['port']}",
            "",
        ]
        
        # Add peer sections
        for peer in enabled_peers:
            peer_dict = {
                'public_key': peer.public_key,
                'pre_shared_key': peer.pre_shared_key,
                'ipv4_address': peer.ipv4_address,
                'ipv6_address': peer.ipv6_address,
                'allowed_ips': peer.allowed_ips,
                'persistent_keepalive': peer.persistent_keepalive
            }
            config_lines.append(wg.generate_server_peer_config(peer_dict, interface['public_key']))
            config_lines.append("")
        
        config = "\n".join(config_lines)
        
        # Save config file
        wg.save_config_file(config)
        
        # Sync configuration
        wg.sync_config()
        
    except PermissionError:
        # If we don't have permission, just log the error
        # In production, the API should run with appropriate permissions
        print("Warning: Cannot update WireGuard config - permission denied")
    except Exception as e:
        print(f"Warning: Failed to update WireGuard config: {str(e)}")

