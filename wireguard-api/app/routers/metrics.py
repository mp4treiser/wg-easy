from fastapi import APIRouter, HTTPException, status
from app.models import MetricsResponse, AllMetricsResponse
from app.database import db
from app.utils.wireguard import WireGuardManager

router = APIRouter()
wg = WireGuardManager()


@router.get("/", response_model=AllMetricsResponse)
async def get_all_metrics():
    """Get metrics for all peers (reads directly from WireGuard)"""
    try:
        # Get peers directly from WireGuard
        wg_peers = wg.dump_peers()
        
        # Get peers from API database to match names
        db_peers = await db.get_all_peers()
        db_peers_by_key = {p.public_key: p for p in db_peers}
        
        metrics_list = []
        enabled_count = 0
        connected_count = 0
        peer_counter = 1
        
        for wg_peer in wg_peers:
            public_key = wg_peer['public_key']
            db_peer = db_peers_by_key.get(public_key)
            
            if db_peer:
                peer_name = db_peer.name
                peer_id = db_peer.id
                is_enabled = db_peer.enabled
            else:
                peer_name = f"peer-{public_key[:8]}"
                peer_id = peer_counter
                peer_counter += 1
                is_enabled = True
            
            if is_enabled:
                enabled_count += 1
            
            metrics = wg.get_peer_metrics(public_key)
            is_connected = False
            
            if metrics:
                transfer_rx_mb = metrics.transfer_rx / (1024 * 1024)
                transfer_tx_mb = metrics.transfer_tx / (1024 * 1024)
                
                # Consider peer connected if handshake was within last 3 minutes
                if metrics.latest_handshake:
                    from datetime import datetime, timedelta
                    if datetime.now() - metrics.latest_handshake < timedelta(minutes=3):
                        is_connected = True
                        if is_enabled:
                            connected_count += 1
                
                metrics_list.append(MetricsResponse(
                    peer_id=peer_id,
                    peer_name=peer_name,
                    public_key=public_key,
                    endpoint=metrics.endpoint,
                    latest_handshake=metrics.latest_handshake,
                    transfer_rx=metrics.transfer_rx,
                    transfer_tx=metrics.transfer_tx,
                    transfer_rx_mb=round(transfer_rx_mb, 2),
                    transfer_tx_mb=round(transfer_tx_mb, 2),
                    is_connected=is_connected
                ))
            else:
                metrics_list.append(MetricsResponse(
                    peer_id=peer_id,
                    peer_name=peer_name,
                    public_key=public_key,
                    endpoint=None,
                    latest_handshake=None,
                    transfer_rx=0,
                    transfer_tx=0,
                    transfer_rx_mb=0.0,
                    transfer_tx_mb=0.0,
                    is_connected=False
                ))
        
        return AllMetricsResponse(
            total_peers=len(wg_peers),
            enabled_peers=enabled_count,
            connected_peers=connected_count,
            peers=metrics_list
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get metrics: {str(e)}"
        )


@router.get("/{peer_id}", response_model=MetricsResponse)
async def get_peer_metrics(peer_id: int):
    """Get metrics for a specific peer"""
    peer = await db.get_peer(peer_id)
    if not peer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Peer {peer_id} not found"
        )
    
    metrics = wg.get_peer_metrics(peer.public_key)
    is_connected = False
    
    if metrics:
        transfer_rx_mb = metrics.transfer_rx / (1024 * 1024)
        transfer_tx_mb = metrics.transfer_tx / (1024 * 1024)
        
        # Consider peer connected if handshake was within last 3 minutes
        if metrics.latest_handshake:
            from datetime import datetime, timedelta
            if datetime.now() - metrics.latest_handshake < timedelta(minutes=3):
                is_connected = True
        
        return MetricsResponse(
            peer_id=peer.id,
            peer_name=peer.name,
            public_key=peer.public_key,
            endpoint=metrics.endpoint,
            latest_handshake=metrics.latest_handshake,
            transfer_rx=metrics.transfer_rx,
            transfer_tx=metrics.transfer_tx,
            transfer_rx_mb=round(transfer_rx_mb, 2),
            transfer_tx_mb=round(transfer_tx_mb, 2),
            is_connected=is_connected
        )
    else:
        return MetricsResponse(
            peer_id=peer.id,
            peer_name=peer.name,
            public_key=peer.public_key,
            endpoint=None,
            latest_handshake=None,
            transfer_rx=0,
            transfer_tx=0,
            transfer_rx_mb=0.0,
            transfer_tx_mb=0.0,
            is_connected=False
        )

