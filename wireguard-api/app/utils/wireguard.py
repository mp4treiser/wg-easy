import subprocess
import re
import logging
import sqlite3
import os
from typing import Optional, List, Dict
from datetime import datetime
from app.models import PeerMetrics

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


class WireGuardManager:
    def __init__(self, interface_name: str = "wg0", wg_executable: str = "wg", 
                 wg_container: str = None):
        self.interface_name = interface_name
        self.wg_executable = wg_executable
        # Get container name from environment or use default
        self.wg_container = wg_container or os.getenv("WG_CONTAINER", "wg-easy")
        # wg-easy database path (shared volume)
        self.wg_easy_db_path = "/etc/wireguard/wg-easy.db"
        logger.info(f"WireGuardManager initialized with interface={interface_name}, executable={wg_executable}, container={self.wg_container}, db_path={self.wg_easy_db_path}")

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
        
        # For client config, use stored allowed_ips (should be 0.0.0.0/0 for internet access)
        # or default to 0.0.0.0/0 if not specified
        allowed_ips = peer.get('allowed_ips', ['0.0.0.0/0'])
        if isinstance(allowed_ips, str):
            allowed_ips = allowed_ips.split(',')
        # Ensure 0.0.0.0/0 is included for internet access unless explicitly restricted
        if not any('0.0.0.0/0' in ip for ip in allowed_ips):
            # If no 0.0.0.0/0, add it first (client needs internet access)
            allowed_ips = ['0.0.0.0/0'] + allowed_ips
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
        """Add a peer to WireGuard interface using wg set and save to config file"""
        try:
            import subprocess
            
            # First add the peer via wg set
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
            
            # Now save to config file and sync
            self._save_peer_to_config(public_key, allowed_ips, pre_shared_key, persistent_keepalive)
            self._sync_config()
            
            return True
        except Exception as e:
            logger.error(f"Failed to add peer: {e}", exc_info=True)
            raise Exception(f"Failed to add peer: {str(e)}")
    
    def _save_peer_to_config(self, public_key: str, allowed_ips: List[str],
                             pre_shared_key: Optional[str] = None,
                             persistent_keepalive: Optional[int] = None):
        """Append peer configuration to WireGuard config file"""
        try:
            config_path = f"/etc/wireguard/{self.interface_name}.conf"
            
            # Read existing config
            with open(config_path, 'r') as f:
                content = f.read()
            
            # Generate peer config block
            peer_config = "\n[Peer]\n"
            peer_config += f"PublicKey = {public_key}\n"
            
            if pre_shared_key:
                peer_config += f"PresharedKey = {pre_shared_key}\n"
            
            if allowed_ips:
                allowed_ips_str = ', '.join(allowed_ips)
                peer_config += f"AllowedIPs = {allowed_ips_str}\n"
            
            if persistent_keepalive:
                peer_config += f"PersistentKeepalive = {persistent_keepalive}\n"
            
            # Append peer config to file (inside container)
            docker_cmd = f"docker exec {self.wg_container} sh -c \"echo '{peer_config}' >> {config_path}\""
            logger.debug(f"Appending peer to config: {docker_cmd}")
            subprocess.run(
                docker_cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            
            logger.info(f"Peer configuration saved to {config_path}")
        except Exception as e:
            logger.warning(f"Failed to save peer to config file (will continue): {e}")
            # Don't fail if we can't write to config file, wg set already applied changes
    
    def _sync_config(self):
        """Sync WireGuard configuration using syncconf"""
        try:
            # Use wg syncconf to apply config file changes without restarting
            # This reads from config file and applies changes
            docker_cmd = f"docker exec {self.wg_container} sh -c \"{self.wg_executable} syncconf {self.interface_name} <({self.wg_executable}-quick strip {self.interface_name})\""
            logger.debug(f"Syncing config: {docker_cmd}")
            subprocess.run(
                docker_cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            logger.info("Config synced successfully")
        except Exception as e:
            logger.warning(f"Failed to sync config (will continue): {e}")
            # Don't fail if sync fails, changes are already applied via wg set
    
    def remove_peer(self, public_key: str) -> bool:
        """Remove a peer from WireGuard interface and config file"""
        try:
            import subprocess
            
            # Remove via wg set
            self._exec(f"{self.wg_executable} set {self.interface_name} peer {public_key} remove")
            
            # Remove from config file
            self._remove_peer_from_config(public_key)
            
            # Sync config
            self._sync_config()
            
            return True
        except Exception as e:
            raise Exception(f"Failed to remove peer: {str(e)}")
    
    def _remove_peer_from_config(self, public_key: str):
        """Remove peer configuration from WireGuard config file"""
        try:
            import subprocess
            config_path = f"/etc/wireguard/{self.interface_name}.conf"
            
            # Read config file inside container
            docker_cmd_read = f"docker exec {self.wg_container} cat {config_path}"
            result = subprocess.run(
                docker_cmd_read,
                shell=True,
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            content = result.stdout
            
            # Remove peer block
            lines = content.split('\n')
            new_lines = []
            skip_peer = False
            
            for line in lines:
                if line.strip() == '[Peer]':
                    skip_peer = True
                    # Check if this peer matches
                    continue
                elif skip_peer:
                    if line.strip().startswith('PublicKey = '):
                        peer_key = line.split('=', 1)[1].strip()
                        if peer_key == public_key:
                            # Skip this entire peer block
                            continue
                        else:
                            # Different peer, keep it
                            new_lines.append('[Peer]')
                            new_lines.append(line)
                            skip_peer = False
                    elif line.strip() and not line.strip().startswith('PublicKey') and not line.strip().startswith('PresharedKey') and not line.strip().startswith('AllowedIPs') and not line.strip().startswith('PersistentKeepalive') and not line.strip().startswith('Endpoint'):
                        # End of peer block or start of new section
                        if not line.strip().startswith('['):
                            new_lines.append('[Peer]')
                        new_lines.append(line)
                        skip_peer = False
                    else:
                        # Part of peer block, but not the one we're removing
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            
            # Write back to file
            new_content = '\n'.join(new_lines)
            docker_cmd_write = f"docker exec {self.wg_container} sh -c \"cat > {config_path} << 'EOF'\n{new_content}\nEOF\""
            subprocess.run(
                docker_cmd_write,
                shell=True,
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            
            logger.info(f"Peer removed from config file")
        except Exception as e:
            logger.warning(f"Failed to remove peer from config file (will continue): {e}")
    
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
    
    def _get_db_connection(self):
        """Get SQLite connection to wg-easy database"""
        try:
            if not os.path.exists(self.wg_easy_db_path):
                logger.warning(f"wg-easy database not found at {self.wg_easy_db_path}")
                return None
            conn = sqlite3.connect(self.wg_easy_db_path)
            conn.row_factory = sqlite3.Row  # Return rows as dict-like objects
            return conn
        except Exception as e:
            logger.error(f"Failed to connect to wg-easy database: {e}")
            return None
    
    def get_peer_from_db(self, public_key: str) -> Optional[Dict]:
        """Get peer information from wg-easy database by public_key"""
        conn = self._get_db_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM clients_table WHERE public_key = ?",
                (public_key,)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        except Exception as e:
            logger.error(f"Failed to get peer from database: {e}")
            return None
        finally:
            conn.close()
    
    def save_peer_to_db(self, peer_data: Dict) -> bool:
        """Save peer to wg-easy database"""
        conn = self._get_db_connection()
        if not conn:
            logger.warning("Cannot save peer to database: connection failed")
            return False
        
        try:
            cursor = conn.cursor()
            
            # Check if peer already exists
            cursor.execute(
                "SELECT id FROM clients_table WHERE public_key = ?",
                (peer_data['public_key'],)
            )
            existing = cursor.fetchone()
            
            if existing:
                # Update existing peer
                cursor.execute("""
                    UPDATE clients_table SET
                        name = ?,
                        ipv4_address = ?,
                        ipv6_address = ?,
                        private_key = ?,
                        pre_shared_key = ?,
                        allowed_ips = ?,
                        server_allowed_ips = ?,
                        persistent_keepalive = ?,
                        enabled = 1,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE public_key = ?
                """, (
                    peer_data.get('name', ''),
                    peer_data.get('ipv4_address', ''),
                    peer_data.get('ipv6_address', ''),
                    peer_data.get('private_key', ''),
                    peer_data.get('pre_shared_key', ''),
                    peer_data.get('allowed_ips', '[]'),  # JSON string
                    peer_data.get('server_allowed_ips', '[]'),  # JSON string
                    peer_data.get('persistent_keepalive', 25),
                    peer_data['public_key']
                ))
            else:
                # Insert new peer
                # First, get user_id and interface_id
                cursor.execute("SELECT id FROM users_table LIMIT 1")
                user_row = cursor.fetchone()
                if not user_row:
                    logger.error("No user found in database")
                    return False
                user_id = user_row[0]
                
                cursor.execute("SELECT name FROM interfaces_table WHERE name = ?", (self.interface_name,))
                interface_row = cursor.fetchone()
                if not interface_row:
                    logger.error(f"Interface {self.interface_name} not found in database")
                    return False
                interface_id = interface_row[0]
                
                # Get default values from userConfig
                cursor.execute("SELECT * FROM user_config_table WHERE id = ?", (self.interface_name,))
                user_config = cursor.fetchone()
                
                default_mtu = 1420
                if user_config:
                    default_mtu = user_config.get('mtu', 1420) if hasattr(user_config, 'get') else 1420
                
                import json
                allowed_ips_json = json.dumps(peer_data.get('allowed_ips', ['0.0.0.0/0']))
                server_allowed_ips_json = json.dumps(peer_data.get('server_allowed_ips', [f"{peer_data.get('ipv4_address', '')}/32"]))
                
                cursor.execute("""
                    INSERT INTO clients_table (
                        user_id, interface_id, name, ipv4_address, ipv6_address,
                        private_key, public_key, pre_shared_key,
                        allowed_ips, server_allowed_ips, persistent_keepalive,
                        mtu, enabled, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """, (
                    user_id,
                    interface_id,
                    peer_data.get('name', ''),
                    peer_data.get('ipv4_address', ''),
                    peer_data.get('ipv6_address', ''),
                    peer_data.get('private_key', ''),
                    peer_data['public_key'],
                    peer_data.get('pre_shared_key', ''),
                    allowed_ips_json,
                    server_allowed_ips_json,
                    peer_data.get('persistent_keepalive', 25),
                    default_mtu
                ))
            
            conn.commit()
            logger.info(f"Peer {peer_data['public_key'][:8]}... saved to database")
            return True
        except Exception as e:
            logger.error(f"Failed to save peer to database: {e}", exc_info=True)
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def delete_peer_from_db(self, public_key: str) -> bool:
        """Delete peer from wg-easy database"""
        conn = self._get_db_connection()
        if not conn:
            logger.warning("Cannot delete peer from database: connection failed")
            return False
        
        try:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM clients_table WHERE public_key = ?",
                (public_key,)
            )
            conn.commit()
            deleted = cursor.rowcount > 0
            if deleted:
                logger.info(f"Peer {public_key[:8]}... deleted from database")
            return deleted
        except Exception as e:
            logger.error(f"Failed to delete peer from database: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()

