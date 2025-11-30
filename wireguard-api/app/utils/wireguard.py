import subprocess
import re
import logging
from typing import Optional, List, Dict
from datetime import datetime
from app.models import PeerMetrics

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


class WireGuardManager:
    def __init__(self, interface_name: str = "wg0", wg_executable: str = "wg", 
                 wg_container: str = None):
        import os
        self.interface_name = interface_name
        self.wg_executable = wg_executable
        # Get container name from environment or use default
        self.wg_container = wg_container or os.getenv("WG_CONTAINER", "wg-easy")
        logger.info(f"WireGuardManager initialized with interface={interface_name}, executable={wg_executable}, container={self.wg_container}")

    def _exec(self, command: str, use_container: bool = True) -> str:
        """Execute shell command and return output"""
        # If use_container is True, execute command inside wg-easy container
        if use_container:
            # Check if we're inside Docker and can access docker command
            # If not, try direct command (for local development)
            try:
                # Try to execute via docker exec first
                docker_command = f"docker exec {self.wg_container} {command}"
                logger.debug(f"Executing command in container: {docker_command}")
                result = subprocess.run(
                    docker_command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10
                )
                logger.debug(f"Command output: {result.stdout}")
                logger.debug(f"Command return code: {result.returncode}")
                return result.stdout.strip()
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
                # If docker exec fails, try direct command (might be running in same container or on host)
                logger.warning(f"Docker exec failed, trying direct command: {e}")
                try:
                    logger.debug(f"Executing command directly: {command}")
                    result = subprocess.run(
                        command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=10
                    )
                    logger.debug(f"Command output: {result.stdout}")
                    logger.debug(f"Command return code: {result.returncode}")
                    return result.stdout.strip()
                except subprocess.CalledProcessError as e2:
                    logger.error(f"Direct command also failed: {command}")
                    logger.error(f"Return code: {e2.returncode}")
                    logger.error(f"Stdout: {e2.stdout}")
                    logger.error(f"Stderr: {e2.stderr}")
                    raise Exception(f"Command failed: {command}\nReturn code: {e2.returncode}\nStdout: {e2.stdout}\nStderr: {e2.stderr}")
        else:
            # Direct execution
            logger.debug(f"Executing command directly: {command}")
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10
                )
                logger.debug(f"Command output: {result.stdout}")
                logger.debug(f"Command return code: {result.returncode}")
                return result.stdout.strip()
            except subprocess.CalledProcessError as e:
                logger.error(f"Command failed: {command}")
                logger.error(f"Return code: {e.returncode}")
                logger.error(f"Stdout: {e.stdout}")
                logger.error(f"Stderr: {e.stderr}")
                raise Exception(f"Command failed: {command}\nReturn code: {e.returncode}\nStdout: {e.stdout}\nStderr: {e.stderr}")

    def generate_private_key(self) -> str:
        """Generate WireGuard private key"""
        # Generate locally, not in container
        return self._exec(f"{self.wg_executable} genkey", use_container=False)

    def get_public_key(self, private_key: str) -> str:
        """Get public key from private key"""
        # Generate locally, not in container
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
        # Generate locally, not in container
        return self._exec(f"{self.wg_executable} genpsk", use_container=False)

    def dump_peers(self) -> List[Dict]:
        """Get peer information from WireGuard dump"""
        logger.info(f"dump_peers() called for interface {self.interface_name}")
        try:
            command = f"{self.wg_executable} show {self.interface_name} dump"
            logger.debug(f"Executing: {command}")
            output = self._exec(command)
            logger.info(f"Raw dump output: {repr(output)}")
            logger.info(f"Output length: {len(output)}")
            
            if not output:
                logger.warning("Empty output from wg dump")
                return []
            
            peers = []
            lines = output.strip().split('\n')
            logger.info(f"Total lines in output: {len(lines)}")
            
            # First line is interface info, skip it
            if len(lines) > 0:
                logger.debug(f"Interface line (skipped): {lines[0]}")
            
            # Process peer lines
            for i, line in enumerate(lines[1:], start=1):
                logger.debug(f"Processing line {i}: {repr(line)}")
                if not line.strip():
                    logger.debug(f"Line {i} is empty, skipping")
                    continue
                    
                parts = line.split('\t')
                logger.debug(f"Line {i} split into {len(parts)} parts: {parts}")
                
                if len(parts) < 8:
                    logger.warning(f"Line {i} has only {len(parts)} parts, expected 8, skipping")
                    continue
                
                try:
                    public_key = parts[0]
                    pre_shared_key = parts[1] if parts[1] != '(none)' else None
                    endpoint = parts[2] if parts[2] != '(none)' else None
                    allowed_ips = parts[3]
                    latest_handshake = parts[4]
                    transfer_rx = int(parts[5]) if parts[5].isdigit() else 0
                    transfer_tx = int(parts[6]) if parts[6].isdigit() else 0
                    persistent_keepalive = parts[7] if len(parts) > 7 else None
                    
                    logger.debug(f"Parsed peer: public_key={public_key[:8]}..., allowed_ips={allowed_ips}")
                    
                    # Convert handshake timestamp
                    handshake_dt = None
                    if latest_handshake and latest_handshake != '0':
                        try:
                            timestamp = int(latest_handshake)
                            handshake_dt = datetime.fromtimestamp(timestamp)
                        except (ValueError, OSError) as e:
                            logger.warning(f"Failed to parse handshake timestamp {latest_handshake}: {e}")
                    
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
                    
                    peer_data = {
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
                    }
                    peers.append(peer_data)
                    logger.info(f"Successfully parsed peer: {public_key[:8]}...")
                except Exception as e:
                    logger.error(f"Error parsing line {i}: {e}", exc_info=True)
                    continue
            
            logger.info(f"dump_peers() returning {len(peers)} peers")
            return peers
        except Exception as e:
            logger.error(f"Exception in dump_peers(): {e}", exc_info=True)
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

    def get_interface_info(self) -> Optional[Dict]:
        """Get WireGuard interface information"""
        logger.info(f"get_interface_info() called for interface {self.interface_name}")
        try:
            command = f"{self.wg_executable} show {self.interface_name}"
            logger.debug(f"Executing: {command}")
            output = self._exec(command)
            logger.info(f"Interface show output: {repr(output)}")
            
            lines = output.strip().split('\n')
            logger.debug(f"Interface output has {len(lines)} lines")
            
            interface_info = {
                'name': self.interface_name,
                'public_key': None,
                'listening_port': None
            }
            
            for line in lines:
                logger.debug(f"Processing interface line: {line}")
                if 'public key:' in line:
                    interface_info['public_key'] = line.split('public key:')[1].strip()
                    logger.debug(f"Found public_key: {interface_info['public_key']}")
                elif 'listening port:' in line:
                    interface_info['listening_port'] = int(line.split('listening port:')[1].strip())
                    logger.debug(f"Found listening_port: {interface_info['listening_port']}")
            
            if interface_info['public_key']:
                logger.info(f"Interface info retrieved: {interface_info}")
                return interface_info
            else:
                logger.warning("No public key found in interface info")
                return None
        except Exception as e:
            logger.error(f"Exception in get_interface_info(): {e}", exc_info=True)
            return None
    
    def add_peer(self, public_key: str, allowed_ips: List[str], 
                 pre_shared_key: Optional[str] = None, 
                 persistent_keepalive: Optional[int] = None) -> bool:
        """Add a peer to WireGuard interface using wg set"""
        try:
            import subprocess
            
            # First add the peer
            self._exec(f"{self.wg_executable} set {self.interface_name} peer {public_key}")
            
            # Set preshared key if provided (using stdin)
            if pre_shared_key:
                # Use echo to pipe preshared key via stdin
                docker_cmd = f"docker exec {self.wg_container} sh -c \"echo '{pre_shared_key}' | {self.wg_executable} set {self.interface_name} peer {public_key} preshared-key /dev/stdin\""
                logger.debug(f"Setting preshared key: {docker_cmd}")
                result = subprocess.run(
                    docker_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10
                )
            
            # Set allowed IPs
            if allowed_ips:
                allowed_ips_str = ','.join(allowed_ips)
                self._exec(f"{self.wg_executable} set {self.interface_name} peer {public_key} allowed-ips {allowed_ips_str}")
            
            # Set persistent keepalive
            if persistent_keepalive:
                self._exec(f"{self.wg_executable} set {self.interface_name} peer {public_key} persistent-keepalive {persistent_keepalive}")
            
            return True
        except Exception as e:
            logger.error(f"Failed to add peer: {e}", exc_info=True)
            raise Exception(f"Failed to add peer: {str(e)}")
    
    def remove_peer(self, public_key: str) -> bool:
        """Remove a peer from WireGuard interface"""
        try:
            self._exec(f"{self.wg_executable} set {self.interface_name} peer {public_key} remove")
            return True
        except Exception as e:
            raise Exception(f"Failed to remove peer: {str(e)}")
    
    def get_next_available_ip(self, cidr: str = "10.8.0.0/24") -> str:
        """Get next available IP address from CIDR"""
        try:
            # Get all existing peers
            peers = self.dump_peers()
            existing_ips = set()
            
            for peer in peers:
                if peer.get('ipv4_address'):
                    existing_ips.add(peer['ipv4_address'])
            
            # Parse CIDR
            base_ip, prefix = cidr.split('/')
            prefix = int(prefix)
            base_parts = base_ip.split('.')
            base_network = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}"
            
            # Find next available IP (starting from .2, as .1 is usually the server)
            for i in range(2, 255):
                ip = f"{base_network}.{i}"
                if ip not in existing_ips:
                    return ip
            
            raise Exception("No available IPv4 addresses")
        except Exception as e:
            raise Exception(f"Failed to get next IP: {str(e)}")
    
    def read_config_file(self) -> Optional[Dict]:
        """Read WireGuard config file to get interface details"""
        try:
            config_path = f"/etc/wireguard/{self.interface_name}.conf"
            with open(config_path, 'r') as f:
                content = f.read()
            
            config = {
                'name': self.interface_name,
                'private_key': None,
                'public_key': None,
                'address': None,
                'listen_port': None,
                'dns': None,
                'endpoint': None
            }
            
            # Parse config file
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('PrivateKey'):
                    config['private_key'] = line.split('=', 1)[1].strip()
                elif line.startswith('Address'):
                    config['address'] = line.split('=', 1)[1].strip()
                elif line.startswith('ListenPort'):
                    config['listen_port'] = int(line.split('=', 1)[1].strip())
                elif line.startswith('DNS'):
                    config['dns'] = line.split('=', 1)[1].strip()
            
            # Get public key from interface if available
            interface_info = self.get_interface_info()
            if interface_info and interface_info.get('public_key'):
                config['public_key'] = interface_info['public_key']
            
            return config
        except FileNotFoundError:
            return None
        except Exception as e:
            return None

