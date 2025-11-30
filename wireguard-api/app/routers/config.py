from fastapi import APIRouter, HTTPException, status
from typing import Optional
from pydantic import BaseModel
from app.database import db
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
    """Get WireGuard interface configuration"""
    interface = await db.get_interface()
    if not interface:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Interface not configured. Please initialize it first."
        )
    
    # Don't expose private key in response
    return {
        "name": interface.get('name', 'wg0'),
        "public_key": interface.get('public_key'),
        "port": interface.get('port'),
        "ipv4_cidr": interface.get('ipv4_cidr'),
        "endpoint": interface.get('endpoint'),
        "dns": interface.get('dns')
    }


@router.post("/interface")
async def init_interface(config: InterfaceConfig):
    """Initialize or update WireGuard interface configuration"""
    try:
        existing = await db.get_interface()
        
        if existing and (config.private_key or config.public_key):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Interface already exists. Cannot change keys."
            )
        
        # Generate keys if not provided
        private_key = config.private_key or wg.generate_private_key()
        public_key = config.public_key or wg.get_public_key(private_key)
        
        await db.init_interface(
            private_key=private_key,
            public_key=public_key,
            port=config.port,
            ipv4_cidr=config.ipv4_cidr,
            endpoint=config.endpoint,
            dns=config.dns
        )
        
        return {
            "message": "Interface initialized successfully",
            "public_key": public_key,
            "port": config.port
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initialize interface: {str(e)}"
        )

