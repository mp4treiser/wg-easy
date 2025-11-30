from fastapi import APIRouter, HTTPException, status
from app.models import MetricsResponse, AllMetricsResponse
from app.utils.wireguard import WireGuardManager

router = APIRouter()
wg = WireGuardManager()


@router.get("/", response_model=AllMetricsResponse)
async def get_all_metrics():
    """Get metrics for all peers (reads directly from WireGuard)"""
    try:
        wg_peers = wg.dump_peers()
        metrics_list = []
        enabled_count = 0
        connected_count = 0
        
        for wg_peer in wg_peers:
            public_key = wg_peer['public_key']
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
                        connected_count += 1
                
                metrics_list.append(MetricsResponse(
                    public_key=public_key,
                    peer_name=f"peer-{public_key[:8]}",
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
                    public_key=public_key,
                    peer_name=f"peer-{public_key[:8]}",
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


@router.get("/{public_key}", response_model=MetricsResponse)
async def get_peer_metrics(public_key: str):
    """Get metrics for a specific peer"""
    wg_peers = wg.dump_peers()
    peer_found = False
    
    for wg_peer in wg_peers:
        if wg_peer['public_key'] == public_key:
            peer_found = True
            break
    
    if not peer_found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Peer {public_key} not found"
        )
    
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
        
        return MetricsResponse(
            public_key=public_key,
            peer_name=f"peer-{public_key[:8]}",
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
            public_key=public_key,
            peer_name=f"peer-{public_key[:8]}",
            endpoint=None,
            latest_handshake=None,
            transfer_rx=0,
            transfer_tx=0,
            transfer_rx_mb=0.0,
            transfer_tx_mb=0.0,
            is_connected=False
        )
