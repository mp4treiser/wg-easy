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


@router.get("/debug")
async def debug_info():
    """Debug endpoint to check WireGuard status"""
    import logging
    logger = logging.getLogger(__name__)
    
    debug_info = {
        "interface_name": wg.interface_name,
        "wg_executable": wg.wg_executable,
        "tests": {}
    }
    
    # Test 1: Check if wg command exists
    try:
        import subprocess
        result = subprocess.run(
            ["which", wg.wg_executable],
            capture_output=True,
            text=True,
            timeout=5
        )
        debug_info["tests"]["wg_command_exists"] = result.returncode == 0
        debug_info["tests"]["wg_command_path"] = result.stdout.strip() if result.returncode == 0 else None
    except Exception as e:
        debug_info["tests"]["wg_command_exists"] = False
        debug_info["tests"]["wg_command_error"] = str(e)
    
    # Test 2: Try to get interface info
    try:
        interface_info = wg.get_interface_info()
        debug_info["tests"]["interface_info"] = interface_info
        debug_info["tests"]["interface_accessible"] = interface_info is not None
    except Exception as e:
        debug_info["tests"]["interface_accessible"] = False
        debug_info["tests"]["interface_error"] = str(e)
    
    # Test 3: Try to dump peers
    try:
        peers = wg.dump_peers()
        debug_info["tests"]["dump_peers_count"] = len(peers)
        debug_info["tests"]["dump_peers_success"] = True
        if peers:
            debug_info["tests"]["sample_peer"] = {
                "public_key": peers[0].get('public_key', '')[:16] + '...',
                "allowed_ips": peers[0].get('allowed_ips', [])
            }
    except Exception as e:
        debug_info["tests"]["dump_peers_success"] = False
        debug_info["tests"]["dump_peers_error"] = str(e)
    
    # Test 4: Try raw wg show command
    try:
        import subprocess
        result = subprocess.run(
            [wg.wg_executable, "show", wg.interface_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        debug_info["tests"]["raw_wg_show_success"] = result.returncode == 0
        debug_info["tests"]["raw_wg_show_output"] = result.stdout[:500] if result.stdout else None
        debug_info["tests"]["raw_wg_show_stderr"] = result.stderr if result.stderr else None
    except Exception as e:
        debug_info["tests"]["raw_wg_show_success"] = False
        debug_info["tests"]["raw_wg_show_error"] = str(e)
    
    # Test 5: Try wg show dump
    try:
        import subprocess
        result = subprocess.run(
            [wg.wg_executable, "show", wg.interface_name, "dump"],
            capture_output=True,
            text=True,
            timeout=5
        )
        debug_info["tests"]["raw_wg_dump_success"] = result.returncode == 0
        debug_info["tests"]["raw_wg_dump_output"] = result.stdout if result.stdout else None
        debug_info["tests"]["raw_wg_dump_stderr"] = result.stderr if result.stderr else None
        debug_info["tests"]["raw_wg_dump_output_lines"] = len(result.stdout.split('\n')) if result.stdout else 0
    except Exception as e:
        debug_info["tests"]["raw_wg_dump_success"] = False
        debug_info["tests"]["raw_wg_dump_error"] = str(e)
    
    return debug_info
