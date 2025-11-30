import subprocess
import re
from typing import Optional, List, Dict
from datetime import datetime
from app.models import PeerMetrics


class WireGuardManager:
    def __init__(self, interface_name: str = "wg0", wg_executable: str = "wg"):
        self.interface_name = interface_name
        self.wg_executable = wg_executable

    def _exec(self, command: str) -> str:
        """Execute shell command and return output"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise Exception(f"Command failed: {command}\nError: {e.stderr}")

    def generate_private_key(self) -> str:
        """Generate WireGuard private key"""
        return self._exec(f"{self.wg_executable} genkey")

    def get_public_key(self, private_key: str) -> str:
        """Get public key from private key"""
        process = subprocess.Popen(
            f"echo '{private_key}' | {self.wg_executable} pubkey",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            raise Exception(f"Failed to generate public key: {stderr}")
        return stdout.strip()

    def generate_pre_shared_key(self) -> str:
        """Generate pre-shared key"""
        return self._exec(f"{self.wg_executable} genpsk")

    def dump_peers(self) -> List[Dict]:
        """Get peer information from WireGuard dump"""
        try:
            output = self._exec(f"{self.wg_executable} show {self.interface_name} dump")
            peers = []
            
            # Skip first line (interface info)
            lines = output.strip().split('\n')[1:]
            
            for line in lines:
                if not line.strip():
                    continue
                    
                parts = line.split('\t')
                if len(parts) < 8:
                    continue
                
                public_key = parts[0]
                pre_shared_key = parts[1] if parts[1] != '(none)' else None
                endpoint = parts[2] if parts[2] != '(none)' else None
                allowed_ips = parts[3]
                latest_handshake = parts[4]
                transfer_rx = int(parts[5]) if parts[5].isdigit() else 0
                transfer_tx = int(parts[6]) if parts[6].isdigit() else 0
                persistent_keepalive = parts[7] if len(parts) > 7 else None
                
                # Convert handshake timestamp
                handshake_dt = None
                if latest_handshake and latest_handshake != '0':
                    try:
                        timestamp = int(latest_handshake)
                        handshake_dt = datetime.fromtimestamp(timestamp)
                    except (ValueError, OSError):
                        pass
                
                # Parse allowed_ips to extract IP addresses
                allowed_ips_list = [ip.strip() for ip in allowed_ips.split(',')] if allowed_ips else []
                ipv4_address = None
                ipv6_address = None
                for ip in allowed_ips_list:
                    if '/' in ip:
                        ip_addr = ip.split('/')[0]
                        if ':' in ip_addr:
                            ipv6_address = ip_addr
                        else:
                            ipv4_address = ip_addr
                
                peers.append({
                    'public_key': public_key,
                    'pre_shared_key': pre_shared_key,
                    'endpoint': endpoint,
                    'allowed_ips': allowed_ips_list,
                    'ipv4_address': ipv4_address,
                    'ipv6_address': ipv6_address,
                    'latest_handshake': handshake_dt,
                    'transfer_rx': transfer_rx,
                    'transfer_tx': transfer_tx,
                    'persistent_keepalive': persistent_keepalive
                })
            
            return peers
        except Exception as e:
            # If interface doesn't exist or no peers, return empty list
            return []

    def get_peer_metrics(self, public_key: str) -> Optional[PeerMetrics]:
        """Get metrics for a specific peer"""
        peers = self.dump_peers()
        for peer in peers:
            if peer['public_key'] == public_key:
                transfer_rx_mb = peer['transfer_rx'] / (1024 * 1024)
                transfer_tx_mb = peer['transfer_tx'] / (1024 * 1024)
                
                return PeerMetrics(
                    public_key=peer['public_key'],
                    endpoint=peer['endpoint'],
                    latest_handshake=peer['latest_handshake'],
                    transfer_rx=peer['transfer_rx'],
                    transfer_tx=peer['transfer_tx'],
                    transfer_rx_mb=round(transfer_rx_mb, 2),
                    transfer_tx_mb=round(transfer_tx_mb, 2)
                )
        return None

    def sync_config(self):
        """Sync WireGuard configuration"""
        try:
            # Use syncconf to update without restarting
            self._exec(
                f"{self.wg_executable} syncconf {self.interface_name} "
                f"<({self.wg_executable}-quick strip {self.interface_name})"
            )
        except Exception:
            # Fallback: restart interface
            self.restart_interface()

    def restart_interface(self):
        """Restart WireGuard interface"""
        try:
            self._exec(f"{self.wg_executable}-quick down {self.interface_name}")
        except:
            pass  # Interface might not be up
        self._exec(f"{self.wg_executable}-quick up {self.interface_name}")

    def generate_server_peer_config(self, peer: Dict, interface_public_key: str) -> str:
        """Generate server-side peer configuration"""
        allowed_ips = peer.get('allowed_ips', [])
        if isinstance(allowed_ips, str):
            allowed_ips = [allowed_ips]
        elif not allowed_ips or len(allowed_ips) == 0:
            allowed_ips = [f"{peer['ipv4_address']}/32"]
            if peer.get('ipv6_address'):
                allowed_ips.append(f"{peer['ipv6_address']}/128")
        
        config = f"[Peer]\n"
        config += f"PublicKey = {peer['public_key']}\n"
        config += f"PresharedKey = {peer['pre_shared_key']}\n"
        config += f"AllowedIPs = {', '.join(allowed_ips)}\n"
        
        persistent_keepalive = peer.get('persistent_keepalive')
        if persistent_keepalive:
            config += f"PersistentKeepalive = {persistent_keepalive}\n"
        
        return config

    def generate_client_config(self, peer: Dict, interface: Dict) -> str:
        """Generate client-side configuration"""
        config = "[Interface]\n"
        config += f"PrivateKey = {peer['private_key']}\n"
        config += f"Address = {peer['ipv4_address']}/32"
        
        if peer.get('ipv6_address'):
            config += f", {peer['ipv6_address']}/128"
        config += "\n"
        
        if interface.get('dns'):
            dns_servers = interface['dns'].split(',') if isinstance(interface['dns'], str) else interface['dns']
            config += f"DNS = {', '.join(dns_servers)}\n"
        
        config += "\n[Peer]\n"
        config += f"PublicKey = {interface['public_key']}\n"
        config += f"PresharedKey = {peer['pre_shared_key']}\n"
        
        allowed_ips = peer.get('allowed_ips', ['0.0.0.0/0'])
        if isinstance(allowed_ips, str):
            allowed_ips = allowed_ips.split(',')
        config += f"AllowedIPs = {', '.join(allowed_ips)}\n"
        
        if peer.get('persistent_keepalive'):
            config += f"PersistentKeepalive = {peer['persistent_keepalive']}\n"
        
        endpoint = interface.get('endpoint')
        port = interface.get('port', 51820)
        if endpoint:
            config += f"Endpoint = {endpoint}:{port}\n"
        
        return config

    def save_config_file(self, config: str):
        """Save configuration to WireGuard config file"""
        config_path = f"/etc/wireguard/{self.interface_name}.conf"
        try:
            with open(config_path, 'w') as f:
                f.write(config)
            # Set proper permissions
            import os
            os.chmod(config_path, 0o600)
        except PermissionError:
            raise Exception(f"Permission denied: Need root access to write to {config_path}")
        except Exception as e:
            raise Exception(f"Failed to save config: {str(e)}")

