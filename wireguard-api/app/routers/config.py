from fastapi import APIRouter, HTTPException, status
from typing import Optional
from pydantic import BaseModel
from app.utils.wireguard import WireGuardManager

router = APIRouter()
wg = WireGuardManager()


class InterfaceConfig(BaseModel):
    private_key: Optional[str] = None
    public_key: Optional[str] = None
    port: int = 51820
    ipv4_cidr: str = "10.8.0.0/24"
    endpoint: Optional[str] = None
    dns: Optional[str] = None


@router.get("/interface")
async def get_interface_config():
    """Get WireGuard interface configuration (reads from WireGuard and config file)"""
    interface_info = wg.get_interface_info()
    config = wg.read_config_file()
    
    if not interface_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="WireGuard interface not found or not running"
        )
    
    result = {
        "name": interface_info.get('name', 'wg0'),
        "public_key": interface_info.get('public_key'),
        "listening_port": interface_info.get('listening_port'),
    }
    
    # Add info from config file if available
    if config:
        if config.get('address'):
            result['address'] = config['address']
        if config.get('dns'):
            result['dns'] = config['dns']
    
    return result


@router.post("/interface")
async def init_interface(config: InterfaceConfig):
    """Initialize WireGuard interface configuration"""
    # This endpoint is kept for compatibility, but interface should be managed by wg-easy
    # We can't create interface here as it's already managed by wg-easy
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Interface is managed by wg-easy. Please configure it through wg-easy web interface."
    )
