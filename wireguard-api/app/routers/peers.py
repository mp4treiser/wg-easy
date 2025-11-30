from fastapi import APIRouter, HTTPException, status, Response
from typing import List
from app.models import PeerCreate, PeerResponse, PeerConfig, peer_keys_store
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
            # Try to get CIDR from config file
            config = wg.read_config_file()
            if config and config.get('address'):
                # Extract CIDR from address
                address = config['address'].split(',')[0]  # Take first address
                if '/' in address:
                    cidr = '.'.join(address.split('/')[0].split('.')[:3]) + '.0/24'
                else:
                    cidr = "10.8.0.0/24"
            else:
                cidr = "10.8.0.0/24"
            
            ipv4_address = wg.get_next_available_ip(cidr)
        
        # Build allowed IPs
        allowed_ips = peer.allowed_ips if peer.allowed_ips else [f"{ipv4_address}/32"]
        if peer.ipv6_address:
            allowed_ips.append(f"{peer.ipv6_address}/128")
        
        # Add peer to WireGuard
        wg.add_peer(
            public_key=public_key,
            allowed_ips=allowed_ips,
            pre_shared_key=pre_shared_key,
            persistent_keepalive=peer.persistent_keepalive
        )
        
        # Store keys in memory (only for peers created via this API)
        peer_keys_store[public_key] = {
            'private_key': private_key,
            'pre_shared_key': pre_shared_key,
            'name': peer.name,
            'ipv4_address': ipv4_address,
            'ipv6_address': peer.ipv6_address
        }
        
        # Get metrics if available
        metrics = wg.get_peer_metrics(public_key)
        
        return PeerResponse(
            public_key=public_key,
            private_key=private_key,
            pre_shared_key=pre_shared_key,
            name=peer.name,
            ipv4_address=ipv4_address,
            ipv6_address=peer.ipv6_address,
            allowed_ips=allowed_ips,
            enabled=True,
            metrics=metrics
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create peer: {str(e)}"
        )


@router.get("/", response_model=List[PeerResponse])
async def list_peers():
    """Get all peers from WireGuard"""
    import logging
    logger = logging.getLogger(__name__)
    logger.info("list_peers() endpoint called")
    
    try:
        logger.info("Calling wg.dump_peers()")
        wg_peers = wg.dump_peers()
        logger.info(f"dump_peers() returned {len(wg_peers)} peers")
        
        result = []
        
        for i, wg_peer in enumerate(wg_peers):
            logger.debug(f"Processing peer {i+1}/{len(wg_peers)}: {wg_peer.get('public_key', 'unknown')[:8]}...")
            public_key = wg_peer['public_key']
            metrics = wg.get_peer_metrics(public_key)
            
            # Get name from store if peer was created via this API
            stored_keys = peer_keys_store.get(public_key, {})
            name = stored_keys.get('name') or f"peer-{public_key[:8]}"
            
            peer_response = PeerResponse(
                public_key=public_key,
                private_key=stored_keys.get('private_key'),
                pre_shared_key=stored_keys.get('pre_shared_key'),
                name=name,
                ipv4_address=stored_keys.get('ipv4_address') or wg_peer.get('ipv4_address'),
                ipv6_address=stored_keys.get('ipv6_address') or wg_peer.get('ipv6_address'),
                allowed_ips=wg_peer.get('allowed_ips', []),
                enabled=True,
                metrics=metrics
            )
            result.append(peer_response)
            logger.debug(f"Added peer to result: {public_key[:8]}...")
        
        logger.info(f"list_peers() returning {len(result)} peers")
        return result
    except Exception as e:
        logger.error(f"Exception in list_peers(): {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list peers: {str(e)}"
        )


@router.get("/by-key", response_model=PeerResponse)
async def get_peer_by_key(public_key: str):
    """Get peer by public key (use query parameter to handle special characters)"""
    from urllib.parse import unquote
    
    # Decode URL-encoded key
    public_key = unquote(public_key)
    
    wg_peers = wg.dump_peers()
    peer_data = None
    
    for wg_peer in wg_peers:
        if wg_peer['public_key'] == public_key:
            peer_data = wg_peer
            break
    
    if not peer_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Peer not found"
        )
    
    metrics = wg.get_peer_metrics(public_key)
    
    # Get name from store if peer was created via this API
    stored_keys = peer_keys_store.get(public_key, {})
    name = stored_keys.get('name') or f"peer-{public_key[:8]}"
    
    return PeerResponse(
        public_key=public_key,
        private_key=stored_keys.get('private_key'),
        pre_shared_key=stored_keys.get('pre_shared_key'),
        name=name,
        ipv4_address=stored_keys.get('ipv4_address') or peer_data.get('ipv4_address'),
        ipv6_address=stored_keys.get('ipv6_address') or peer_data.get('ipv6_address'),
        allowed_ips=peer_data.get('allowed_ips', []),
        enabled=True,
        metrics=metrics
    )


@router.delete("/by-key", status_code=status.HTTP_204_NO_CONTENT)
async def delete_peer(public_key: str):
    """Delete a peer by public key (use query parameter)"""
    from urllib.parse import unquote
    
    # Decode URL-encoded key
    public_key = unquote(public_key)
    
    try:
        wg.remove_peer(public_key)
        # Remove from keys store if exists
        if public_key in peer_keys_store:
            del peer_keys_store[public_key]
        return None
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete peer: {str(e)}"
        )


@router.get("/by-key/config", response_model=PeerConfig)
async def get_peer_config(public_key: str):
    """Get peer configuration (keys and config parameters)"""
    from urllib.parse import unquote
    
    # Decode URL-encoded key
    public_key = unquote(public_key)
    
    wg_peers = wg.dump_peers()
    peer_data = None
    
    for wg_peer in wg_peers:
        if wg_peer['public_key'] == public_key:
            peer_data = wg_peer
            break
    
    if not peer_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Peer not found"
        )
    
    # Get interface info
    interface_info = wg.get_interface_info()
    config = wg.read_config_file()
    
    if not interface_info:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="WireGuard interface not found"
        )
    
    allowed_ips = peer_data.get('allowed_ips', ['0.0.0.0/0'])
    dns = None
    if config and config.get('dns'):
        dns = [d.strip() for d in config['dns'].split(',')]
    
    # Check if we have keys in store (peer created via this API)
    stored_keys = peer_keys_store.get(public_key, {})
    
    return PeerConfig(
        private_key=stored_keys.get('private_key'),  # Only if created via this API
        public_key=public_key,
        pre_shared_key=stored_keys.get('pre_shared_key') or peer_data.get('pre_shared_key'),
        ipv4_address=stored_keys.get('ipv4_address') or peer_data.get('ipv4_address'),
        ipv6_address=stored_keys.get('ipv6_address') or peer_data.get('ipv6_address'),
        allowed_ips=allowed_ips,
        persistent_keepalive=int(peer_data.get('persistent_keepalive', 0)) if peer_data.get('persistent_keepalive') else None,
        server_public_key=interface_info['public_key'],
        server_endpoint=None,  # Not available from WireGuard dump
        server_port=interface_info.get('listening_port', 51820),
        dns=dns
    )


@router.get("/by-key/config/text", response_class=Response)
async def get_peer_config_text(public_key: str):
    """Get peer configuration as text (WireGuard config format)"""
    from urllib.parse import unquote
    
    # Decode URL-encoded key
    public_key = unquote(public_key)
    
    wg_peers = wg.dump_peers()
    peer_data = None
    
    for wg_peer in wg_peers:
        if wg_peer['public_key'] == public_key:
            peer_data = wg_peer
            break
    
    if not peer_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Peer not found"
        )
    
    config = wg.read_config_file()
    interface_info = wg.get_interface_info()
    
    if not config or not interface_info:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="WireGuard interface configuration not found"
        )
    
    # Check if we have keys in store (peer created via this API)
    stored_keys = peer_keys_store.get(public_key, {})
    
    if stored_keys.get('private_key'):
        # Generate full client config
        peer_dict = {
            'private_key': stored_keys['private_key'],
            'ipv4_address': stored_keys.get('ipv4_address') or peer_data.get('ipv4_address'),
            'ipv6_address': stored_keys.get('ipv6_address') or peer_data.get('ipv6_address'),
            'allowed_ips': ['0.0.0.0/0'],  # Default for client
            'pre_shared_key': stored_keys.get('pre_shared_key'),
            'persistent_keepalive': peer_data.get('persistent_keepalive')
        }
        
        interface_dict = {
            'public_key': interface_info['public_key'],
            'port': interface_info.get('listening_port', 51820),
            'dns': config.get('dns') if config else None
        }
        
        config_text = wg.generate_client_config(peer_dict, interface_dict)
    else:
        # Can't generate full config without private key
        config_text = f"# Peer: {public_key[:8]}...\n"
        config_text += f"# Public Key: {public_key}\n"
        config_text += f"# Allowed IPs: {', '.join(peer_data.get('allowed_ips', []))}\n"
        config_text += f"# Server Public Key: {interface_info['public_key']}\n"
        config_text += f"# Server Port: {interface_info.get('listening_port', 51820)}\n"
        config_text += "\n# Note: Full client config is only available for peers created via this API.\n"
        config_text += "# Private key is not stored for peers created through wg-easy.\n"
    
    return Response(
        content=config_text,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="wg-peer-{public_key[:8]}.conf"'
        }
    )


@router.get("/by-key/qrcode")
async def get_peer_qrcode(public_key: str, format: str = "png"):
    """Get QR code for peer configuration (PNG or SVG)"""
    from urllib.parse import unquote
    import qrcode
    import io
    
    # Decode URL-encoded key
    public_key = unquote(public_key)
    
    wg_peers = wg.dump_peers()
    peer_data = None
    
    for wg_peer in wg_peers:
        if wg_peer['public_key'] == public_key:
            peer_data = wg_peer
            break
    
    if not peer_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Peer not found"
        )
    
    config = wg.read_config_file()
    interface_info = wg.get_interface_info()
    
    if not config or not interface_info:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="WireGuard interface configuration not found"
        )
    
    # Check if we have keys in store (peer created via this API)
    stored_keys = peer_keys_store.get(public_key, {})
    
    if not stored_keys.get('private_key'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="QR code is only available for peers created via this API. Private key is required."
        )
    
    # Generate client config
    peer_dict = {
        'private_key': stored_keys['private_key'],
        'ipv4_address': stored_keys.get('ipv4_address') or peer_data.get('ipv4_address'),
        'ipv6_address': stored_keys.get('ipv6_address') or peer_data.get('ipv6_address'),
        'allowed_ips': ['0.0.0.0/0'],  # Default for client
        'pre_shared_key': stored_keys.get('pre_shared_key'),
        'persistent_keepalive': peer_data.get('persistent_keepalive')
    }
    
    interface_dict = {
        'public_key': interface_info['public_key'],
        'port': interface_info.get('listening_port', 51820),
        'dns': config.get('dns') if config else None
    }
    
    config_text = wg.generate_client_config(peer_dict, interface_dict)
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(config_text)
    qr.make(fit=True)
    
    if format.lower() == "svg":
        # Generate SVG
        import qrcode.image.svg
        factory = qrcode.image.svg.SvgImage
        img = qr.make_image(image_factory=factory)
        output = io.BytesIO()
        img.save(output)
        output.seek(0)
        
        return Response(
            content=output.getvalue(),
            media_type="image/svg+xml",
            headers={
                "Content-Disposition": f'inline; filename="wg-peer-{public_key[:8]}.svg"'
            }
        )
    else:
        # Generate PNG (default)
        img = qr.make_image(fill_color="black", back_color="white")
        output = io.BytesIO()
        img.save(output, format='PNG')
        output.seek(0)
        
        return Response(
            content=output.getvalue(),
            media_type="image/png",
            headers={
                "Content-Disposition": f'inline; filename="wg-peer-{public_key[:8]}.png"'
            }
        )
