#!/usr/bin/env python3
"""
Server OS Upgrade Automation Script for Juniper Apstra
=====================================================

This script automates the server OS upgrade process by:
1. Converting LACP active LAGs to static LAGs
2. Disabling one LAG member for redundancy
3. Assigning server to OS upgrade VLAN
4. Waiting for OS upgrade completion
5. Re-enabling LAG member
6. Converting back to LACP active LAGs
7. Assigning server to business VLAN

Based on the dual-LAG topology described in VLAN_Assignment_API.json
"""

import httpx
import json
import time
import sys
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server_os_upgrade.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class UpgradePhase(Enum):
    """Upgrade phases for tracking progress"""
    INIT = "initialization"
    PRE_UPGRADE = "pre_upgrade"
    OS_UPGRADE = "os_upgrade"
    POST_UPGRADE = "post_upgrade"
    COMPLETE = "complete"
    FAILED = "failed"

@dataclass
class ServerConfig:
    """Server configuration for upgrade"""
    server_name: str
    server_id: str
    server_label: str
    routing_zone: str
    os_virtual_network: str
    business_virtual_network: str
    lag_connections: List[Dict]
    interface_ids: List[str]

@dataclass
class ApstraConfig:
    """Apstra server configuration"""
    server_url: str
    username: str
    password: str
    blueprint_name: str
    blueprint_id: str = None  # Resolved from blueprint_name

class ApstraClient:
    """Apstra API client for server upgrade operations"""
    
    def __init__(self, config: ApstraConfig):
        self.config = config
        self.headers = None
        self.server = config.server_url
        self._authenticate()
        
        # Resolve blueprint ID from name
        if not config.blueprint_name:
            raise ValueError("blueprint_name must be provided")
        self.config.blueprint_id = self._resolve_blueprint_id(config.blueprint_name)
    
    def _authenticate(self) -> None:
        """Authenticate with Apstra server"""
        try:
            url_login = f'https://{self.server}/api/user/login'
            headers_init = {
                'Content-Type': "application/json", 
                'Cache-Control': "no-cache"
            }
            data = {
                "username": self.config.username,
                "password": self.config.password
            }
            
            response = httpx.post(
                url_login, 
                json=data, 
                headers=headers_init, 
                verify=False,
                timeout=30.0
            )
            response.raise_for_status()
            
            auth_token = response.json()['token']
            self.headers = {
                'AuthToken': auth_token,
                'Content-Type': "application/json",
                'Cache-Control': "no-cache"
            }
            logger.info("Successfully authenticated with Apstra")
            
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            raise
    
    def _resolve_blueprint_id(self, blueprint_name: str) -> str:
        """Resolve blueprint name to blueprint ID"""
        try:
            url = f'https://{self.server}/api/blueprints'
            response = httpx.get(url, headers=self.headers, verify=False, timeout=30.0)
            response.raise_for_status()
            
            blueprints = response.json().get('items', [])
            
            # Look for exact match first
            for bp in blueprints:
                if bp.get('label') == blueprint_name:
                    logger.info(f"Found blueprint '{blueprint_name}' with ID: {bp['id']}")
                    return bp['id']
            
            # Look for case-insensitive match
            for bp in blueprints:
                if bp.get('label', '').lower() == blueprint_name.lower():
                    logger.info(f"Found blueprint '{blueprint_name}' (case-insensitive) with ID: {bp['id']}")
                    return bp['id']
            
            # List available blueprints for user reference
            available_bps = [bp.get('label', 'Unknown') for bp in blueprints]
            raise ValueError(f"Blueprint '{blueprint_name}' not found. Available blueprints: {available_bps}")
            
        except Exception as e:
            logger.error(f"Failed to resolve blueprint name '{blueprint_name}': {e}")
            raise
    
    def get_system_info(self) -> Dict:
        """Get system information from blueprint"""
        try:
            url = f'https://{self.server}/api/blueprints/{self.config.blueprint_id}/experience/web/system-info'
            response = httpx.get(url, headers=self.headers, verify=False, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
            raise
    
    def get_cabling_map(self) -> Dict:
        """Get cabling map from blueprint"""
        try:
            url = f'https://{self.server}/api/blueprints/{self.config.blueprint_id}/experience/web/cabling-map'
            response = httpx.get(url, headers=self.headers, verify=False, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get cabling map: {e}")
            raise
    
    def get_connectivity_templates(self) -> Dict:
        """Get connectivity templates (policies)"""
        try:
            url = f'https://{self.server}/api/blueprints/{self.config.blueprint_id}/obj-policy-export'
            response = httpx.get(url, headers=self.headers, verify=False, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get connectivity templates: {e}")
            raise
    
    def get_application_endpoints(self) -> Dict:
        """Get application endpoints for policy assignment"""
        try:
            url = f'https://{self.server}/api/blueprints/{self.config.blueprint_id}/obj-policy-application-points'
            response = httpx.post(url, headers=self.headers, verify=False, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get application endpoints: {e}")
            raise
    
    def get_routing_zones(self) -> Dict:
        """Get routing zones (security zones) from blueprint"""
        try:
            url = f'https://{self.server}/api/blueprints/{self.config.blueprint_id}/security-zones'
            response = httpx.get(url, headers=self.headers, verify=False, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get routing zones: {e}")
            raise
    
    def get_virtual_networks(self) -> Dict:
        """Get virtual networks from blueprint"""
        try:
            url = f'https://{self.server}/api/blueprints/{self.config.blueprint_id}/virtual-networks'
            response = httpx.get(url, headers=self.headers, verify=False, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get virtual networks: {e}")
            raise
    
    def change_lag_mode(self, link_ids: List[str], lag_mode: str) -> Dict:
        """Change LAG mode for specified links"""
        try:
            url = f'https://{self.server}/api/blueprints/{self.config.blueprint_id}/leaf-server-link-labels'
            
            links_data = {}
            for link_id in link_ids:
                links_data[link_id] = {
                    "group_label": "dual-link",
                    "lag_mode": lag_mode
                }
            
            payload = {"links": links_data}
            
            response = httpx.patch(
                url, 
                json=payload, 
                headers=self.headers, 
                verify=False, 
                timeout=30.0
            )
            response.raise_for_status()
            logger.info(f"Successfully changed LAG mode to {lag_mode} for {len(link_ids)} links")
            return response.json()
            
        except Exception as e:
            logger.error(f"Failed to change LAG mode to {lag_mode}: {e}")
            raise
    
    def set_interface_state(self, interface_id: str, state: str) -> Dict:
        """Set interface operational state (up/admin_down)"""
        try:
            url = f'https://{self.server}/api/blueprints/{self.config.blueprint_id}/interface-operation-state?experimental=true'
            
            payload = {
                "interfaces": {
                    interface_id: state
                }
            }
            
            response = httpx.patch(
                url, 
                json=payload, 
                headers=self.headers, 
                verify=False, 
                timeout=30.0
            )
            response.raise_for_status()
            logger.info(f"Successfully set interface {interface_id} to {state}")
            return response.json()
            
        except Exception as e:
            logger.error(f"Failed to set interface {interface_id} to {state}: {e}")
            raise
    
    def apply_vlan_policy(self, application_point_id: str, policy_id: str, apply: bool = True) -> Dict:
        """Apply or remove VLAN policy from application point"""
        try:
            url = f'https://{self.server}/api/blueprints/{self.config.blueprint_id}/obj-policy-batch-apply?async=full'
            
            payload = {
                "application_points": [
                    {
                        "id": application_point_id,
                        "policies": [
                            {
                                "policy": policy_id,
                                "used": apply
                            }
                        ]
                    }
                ]
            }
            
            response = httpx.patch(
                url, 
                json=payload, 
                headers=self.headers, 
                verify=False, 
                timeout=30.0
            )
            response.raise_for_status()
            action = "applied" if apply else "removed"
            logger.info(f"Successfully {action} policy {policy_id} to/from application point {application_point_id}")
            return response.json()
            
        except Exception as e:
            action = "apply" if apply else "remove"
            logger.error(f"Failed to {action} policy {policy_id}: {e}")
            raise
    
    def get_diff_status(self) -> Dict:
        """Get configuration diff status"""
        try:
            url = f'https://{self.server}/api/blueprints/{self.config.blueprint_id}/diff-status'
            response = httpx.get(url, headers=self.headers, verify=False, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get diff status: {e}")
            raise
    
    def deploy_configuration(self, description: str) -> Dict:
        """Deploy configuration changes"""
        try:
            # Get current staging version
            diff_status = self.get_diff_status()
            staging_version = diff_status.get('staging_version')
            
            if not staging_version:
                raise ValueError("No staging version found")
            
            url = f'https://{self.server}/api/blueprints/{self.config.blueprint_id}/deploy'
            
            payload = {
                "version": staging_version,
                "description": description
            }
            
            response = httpx.put(
                url, 
                json=payload, 
                headers=self.headers, 
                verify=False, 
                timeout=60.0
            )
            response.raise_for_status()
            logger.info(f"Successfully deployed configuration: {description}")
            return response.json()
            
        except Exception as e:
            logger.error(f"Failed to deploy configuration: {e}")
            raise

class ServerUpgradeManager:
    """Main class to manage server OS upgrade process"""
    
    def __init__(self, apstra_client: ApstraClient):
        self.client = apstra_client
        self.server_config: Optional[ServerConfig] = None
        self.phase = UpgradePhase.INIT
        self.policies = {}
        self.application_points = {}
        
    def discover_server(self, server_name: str) -> ServerConfig:
        """Discover server configuration from Apstra"""
        logger.info(f"Discovering server configuration for: {server_name}")
        
        # Get system info
        system_info = self.client.get_system_info()
        
        # Find the server
        server_data = None
        for system in system_info.get('data', []):
            if (system.get('label', '').lower() == server_name.lower() or 
                system.get('hostname', '').lower() == server_name.lower()):
                server_data = system
                break
        
        if not server_data:
            raise ValueError(f"Server '{server_name}' not found in blueprint")
        
        logger.info(f"Found server: {server_data['label']} (ID: {server_data['id']})")
        
        # Get cabling information
        cabling_map = self.client.get_cabling_map()
        
        # Find LAG connections for this server
        lag_connections = []
        interface_ids = []
        
        for link in cabling_map.get('links', []):
            if link.get('role') == 'to_generic' and 'dual-link' in link.get('group_label', ''):
                # Check if this link involves our server
                for endpoint in link.get('endpoints', []):
                    if endpoint['system']['id'] == server_data['id']:
                        lag_connections.append(link)
                        # Get the leaf interface ID (the other endpoint)
                        for ep in link['endpoints']:
                            if ep['system']['id'] != server_data['id']:
                                interface_ids.append(ep['interface']['id'])
                        break
        
        if not lag_connections:
            raise ValueError(f"No dual-link LAG connections found for server {server_name}")
        
        logger.info(f"Found {len(lag_connections)} LAG connections with {len(interface_ids)} interfaces")
        
        return ServerConfig(
            server_name=server_name,
            server_id=server_data['id'],
            server_label=server_data['label'],
            routing_zone="",  # Will be set later
            os_virtual_network="",  # Will be set later
            business_virtual_network="",  # Will be set later
            lag_connections=lag_connections,
            interface_ids=interface_ids
        )
    
    def discover_network_policies(self, routing_zone: str, os_vn_name: str, business_vn_name: str) -> Tuple[str, str, str]:
        """Discover virtual network policies and application points"""
        logger.info(f"Discovering policies for routing zone '{routing_zone}', OS VN '{os_vn_name}', Business VN '{business_vn_name}'")
        
        # Get routing zones to validate the specified routing zone exists
        rz_response = self.client.get_routing_zones()
        logger.info(f"Routing zones response type: {type(rz_response)}")
        
        routing_zone_id = None
        if isinstance(rz_response, dict):
            for rz_id, rz_data in rz_response.items():
                if isinstance(rz_data, dict) and rz_data.get('label') == routing_zone:
                    routing_zone_id = rz_id
                    logger.info(f"Found routing zone '{routing_zone}' with ID: {routing_zone_id}")
                    break
        
        if not routing_zone_id:
            available_rz = []
            if isinstance(rz_response, dict):
                available_rz = [rz_data.get('label', 'Unknown') for rz_data in rz_response.values() if isinstance(rz_data, dict)]
            raise ValueError(f"Routing zone '{routing_zone}' not found. Available routing zones: {available_rz}")
        
        # Get virtual networks
        vn_response = self.client.get_virtual_networks()
        logger.info(f"Virtual networks response type: {type(vn_response)}")
        
        os_vn_id = None
        business_vn_id = None
        
        if isinstance(vn_response, dict):
            for vn_id, vn_data in vn_response.items():
                if isinstance(vn_data, dict):
                    vn_label = vn_data.get('label', '')
                    vn_security_zone = vn_data.get('security_zone_id', '')
                    
                    # Check if this VN is in our routing zone and matches our names
                    if vn_security_zone == routing_zone_id:
                        if vn_label == os_vn_name:
                            os_vn_id = vn_id
                            logger.info(f"Found OS virtual network '{os_vn_name}' with ID: {os_vn_id}")
                        elif vn_label == business_vn_name:
                            business_vn_id = vn_id
                            logger.info(f"Found business virtual network '{business_vn_name}' with ID: {business_vn_id}")
        
        # Get connectivity templates to find policies for these virtual networks
        ct_response = self.client.get_connectivity_templates()
        logger.info(f"Connectivity templates response type: {type(ct_response)}")
        
        os_policy_id = None
        business_policy_id = None
        
        if isinstance(ct_response, dict):
            for policy_id, policy_data in ct_response.items():
                if isinstance(policy_data, dict) and policy_data.get('visible', False):
                    # Check if this policy is associated with our virtual networks
                    policy_attributes = policy_data.get('attributes', {})
                    if isinstance(policy_attributes, dict):
                        vn_id = policy_attributes.get('vn_id')
                        if vn_id == os_vn_id:
                            os_policy_id = policy_id
                            logger.info(f"Found OS policy ID: {os_policy_id}")
                        elif vn_id == business_vn_id:
                            business_policy_id = policy_id
                            logger.info(f"Found business policy ID: {business_policy_id}")
        
        # Get application endpoints
        app_endpoints_response = self.client.get_application_endpoints()
        logger.info(f"Application endpoints response type: {type(app_endpoints_response)}")
        
        # Parse the response - it has 'application_points' key
        if isinstance(app_endpoints_response, dict):
            app_endpoints = app_endpoints_response.get('application_points', app_endpoints_response)
        else:
            app_endpoints = app_endpoints_response
        
        # Find application point for our server
        server_app_point_id = None
        if isinstance(app_endpoints, list):
            for app_point in app_endpoints:
                # Check if app_point is a dictionary and contains our server reference
                if isinstance(app_point, dict):
                    if self.server_config and self.server_config.server_id in str(app_point):
                        server_app_point_id = app_point.get('id')
                        logger.info(f"Found server application point ID: {server_app_point_id}")
                        break
                # If app_point is a string (ID), check if it relates to our server
                elif isinstance(app_point, str):
                    if self.server_config and self.server_config.server_id in app_point:
                        server_app_point_id = app_point
                        logger.info(f"Found server application point ID: {server_app_point_id}")
                        break
        
        if not os_policy_id:
            logger.warning(f"Could not discover policy for OS virtual network '{os_vn_name}'")
        if not business_policy_id:
            logger.warning(f"Could not discover policy for business virtual network '{business_vn_name}'")
        if not server_app_point_id:
            logger.warning("Could not discover server application point")
        
        return os_policy_id, business_policy_id, server_app_point_id
    
    def pre_upgrade_phase(self) -> None:
        """Execute pre-upgrade phase"""
        logger.info("=== Starting Pre-Upgrade Phase ===")
        self.phase = UpgradePhase.PRE_UPGRADE
        
        if not self.server_config:
            raise ValueError("Server configuration not initialized")
        
        try:
            # Step 1: Change LAG mode to static
            logger.info("Step 1: Converting LACP active LAGs to static LAGs")
            link_ids = [link['id'] for link in self.server_config.lag_connections]
            self.client.change_lag_mode(link_ids, "static_lag")
            
            # Step 2: Disable one interface from each LAG pair
            logger.info("Step 2: Disabling one interface from each LAG pair for redundancy")
            # Disable every second interface (this assumes pairs)
            interfaces_to_disable = self.server_config.interface_ids[1::2]
            for interface_id in interfaces_to_disable:
                self.client.set_interface_state(interface_id, "admin_down")
            
            # Step 3: Apply OS virtual network policy
            if self.policies.get('os_policy_id') and self.application_points.get('server_app_point_id'):
                logger.info(f"Step 3: Assigning server to OS virtual network '{self.server_config.os_virtual_network}'")
                self.client.apply_vlan_policy(
                    self.application_points['server_app_point_id'],
                    self.policies['os_policy_id'],
                    apply=True
                )
            else:
                logger.warning("Skipping virtual network assignment - policies not discovered")
            
            # Step 4: Deploy configuration
            logger.info("Step 4: Deploying pre-upgrade configuration")
            self.client.deploy_configuration("Pre-upgrade: Convert to static LAG and assign OS VLAN")
            
            logger.info("=== Pre-Upgrade Phase Completed ===")
            
        except Exception as e:
            self.phase = UpgradePhase.FAILED
            logger.error(f"Pre-upgrade phase failed: {e}")
            raise
    
    def post_upgrade_phase(self) -> None:
        """Execute post-upgrade phase"""
        logger.info("=== Starting Post-Upgrade Phase ===")
        self.phase = UpgradePhase.POST_UPGRADE
        
        if not self.server_config:
            raise ValueError("Server configuration not initialized")
        
        try:
            # Step 1: Re-enable disabled interfaces
            logger.info("Step 1: Re-enabling previously disabled interfaces")
            interfaces_to_enable = self.server_config.interface_ids[1::2]
            for interface_id in interfaces_to_enable:
                self.client.set_interface_state(interface_id, "up")
            
            # Step 2: Change LAG mode back to LACP active
            logger.info("Step 2: Converting static LAGs back to LACP active")
            link_ids = [link['id'] for link in self.server_config.lag_connections]
            self.client.change_lag_mode(link_ids, "lacp_active")
            
            # Step 3: Remove OS virtual network policy
            if self.policies.get('os_policy_id') and self.application_points.get('server_app_point_id'):
                logger.info(f"Step 3: Removing OS virtual network '{self.server_config.os_virtual_network}' assignment")
                self.client.apply_vlan_policy(
                    self.application_points['server_app_point_id'],
                    self.policies['os_policy_id'],
                    apply=False
                )
            else:
                logger.warning("Skipping OS virtual network removal - policies not discovered")
            
            # Step 4: Apply business virtual network policy
            if self.policies.get('business_policy_id') and self.application_points.get('server_app_point_id'):
                logger.info(f"Step 4: Assigning server to business virtual network '{self.server_config.business_virtual_network}'")
                self.client.apply_vlan_policy(
                    self.application_points['server_app_point_id'],
                    self.policies['business_policy_id'],
                    apply=True
                )
            else:
                logger.warning("Skipping business virtual network assignment - policies not discovered")
            
            # Step 5: Deploy final configuration
            logger.info("Step 5: Deploying post-upgrade configuration")
            self.client.deploy_configuration("Post-upgrade: Restore LACP and assign business VLAN")
            
            self.phase = UpgradePhase.COMPLETE
            logger.info("=== Post-Upgrade Phase Completed ===")
            
        except Exception as e:
            self.phase = UpgradePhase.FAILED
            logger.error(f"Post-upgrade phase failed: {e}")
            raise
    
    def run_upgrade(self, server_name: str, routing_zone: str, os_vn_name: str, business_vn_name: str, 
                   auto_complete: bool = False) -> None:
        """Run the complete upgrade process"""
        try:
            # Initialize
            logger.info(f"Starting server OS upgrade for: {server_name}")
            logger.info(f"Routing zone: {routing_zone}, OS VN: {os_vn_name}, Business VN: {business_vn_name}")
            
            # Discover server
            self.server_config = self.discover_server(server_name)
            self.server_config.routing_zone = routing_zone
            self.server_config.os_virtual_network = os_vn_name
            self.server_config.business_virtual_network = business_vn_name
            
            # Discover policies
            os_policy_id, business_policy_id, server_app_point_id = self.discover_network_policies(
                routing_zone, os_vn_name, business_vn_name
            )
            
            self.policies = {
                'os_policy_id': os_policy_id,
                'business_policy_id': business_policy_id
            }
            self.application_points = {
                'server_app_point_id': server_app_point_id
            }
            
            # Execute pre-upgrade phase
            self.pre_upgrade_phase()
            
            if auto_complete:
                logger.info("Auto-complete mode: Proceeding directly to post-upgrade phase")
                self.post_upgrade_phase()
            else:
                logger.info("Pre-upgrade completed. Server is ready for OS upgrade.")
                logger.info("Run the script again with --post-upgrade flag after OS upgrade is complete.")
        
        except Exception as e:
            logger.error(f"Upgrade process failed: {e}")
            raise

def load_config(config_file: str, blueprint_name: str = None) -> ApstraConfig:
    """Load Apstra configuration from JSON file"""
    try:
        with open(config_file, 'r') as f:
            config_data = json.load(f)
        
        # Use command line blueprint_name if provided, otherwise use config file
        final_blueprint_name = blueprint_name or config_data.get('blueprint_name')
        
        if not final_blueprint_name:
            raise ValueError("blueprint_name must be provided either in config file or command line")
        
        return ApstraConfig(
            server_url=config_data.get('server') or config_data.get('aos_server'),
            username=config_data.get('username'),
            password=config_data.get('password'),
            blueprint_name=final_blueprint_name
        )
    except Exception as e:
        logger.error(f"Failed to load config from {config_file}: {e}")
        raise

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Server OS Upgrade Automation for Juniper Apstra')
    
    # Required arguments
    parser.add_argument('--server-name', '-s', required=True,
                       help='Server name/label to upgrade')
    parser.add_argument('--blueprint-name', '-bp', 
                       help='Blueprint name where the server is located (can also be specified in config file)')
    parser.add_argument('--routing-zone', '-rz', required=True,
                       help='Routing zone name containing both virtual networks')
    parser.add_argument('--os-vn', '-os', required=True,
                       help='OS upgrade virtual network name')
    parser.add_argument('--business-vn', '-bvn', required=True,
                       help='Business virtual network name')
    
    # Optional arguments
    parser.add_argument('--config', '-c', default='apstra_config.json',
                       help='Apstra configuration file (default: apstra_config.json)')
    parser.add_argument('--post-upgrade', action='store_true',
                       help='Run only post-upgrade phase (after OS upgrade is complete)')
    parser.add_argument('--auto-complete', action='store_true',
                       help='Automatically run both pre and post upgrade phases')
    parser.add_argument('--dry-run', action='store_true',
                       help='Dry run mode - discover configuration but make no changes')
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        apstra_config = load_config(args.config, args.blueprint_name)
        
        # Create client
        client = ApstraClient(apstra_config)
        
        # Create upgrade manager
        upgrade_manager = ServerUpgradeManager(client)
        
        if args.dry_run:
            logger.info("=== DRY RUN MODE ===")
            server_config = upgrade_manager.discover_server(args.server_name)
            server_config.routing_zone = args.routing_zone
            server_config.os_virtual_network = args.os_vn
            server_config.business_virtual_network = args.business_vn
            
            logger.info(f"Server Configuration:")
            logger.info(f"  Name: {server_config.server_name}")
            logger.info(f"  ID: {server_config.server_id}")
            logger.info(f"  LAG Connections: {len(server_config.lag_connections)}")
            logger.info(f"  Interface IDs: {server_config.interface_ids}")
            logger.info(f"  Routing Zone: {server_config.routing_zone}")
            logger.info(f"  OS Virtual Network: {server_config.os_virtual_network}")
            logger.info(f"  Business Virtual Network: {server_config.business_virtual_network}")
            
            os_policy, business_policy, app_point = upgrade_manager.discover_network_policies(
                args.routing_zone, args.os_vn, args.business_vn
            )
            logger.info(f"  OS Policy ID: {os_policy}")
            logger.info(f"  Business Policy ID: {business_policy}")
            logger.info(f"  Application Point ID: {app_point}")
            
        elif args.post_upgrade:
            logger.info("Running POST-UPGRADE phase only")
            upgrade_manager.server_config = upgrade_manager.discover_server(args.server_name)
            upgrade_manager.server_config.routing_zone = args.routing_zone
            upgrade_manager.server_config.os_virtual_network = args.os_vn
            upgrade_manager.server_config.business_virtual_network = args.business_vn
            
            os_policy_id, business_policy_id, server_app_point_id = upgrade_manager.discover_network_policies(
                args.routing_zone, args.os_vn, args.business_vn
            )
            
            upgrade_manager.policies = {
                'os_policy_id': os_policy_id,
                'business_policy_id': business_policy_id
            }
            upgrade_manager.application_points = {
                'server_app_point_id': server_app_point_id
            }
            
            upgrade_manager.post_upgrade_phase()
            
        else:
            # Run full upgrade process
            upgrade_manager.run_upgrade(
                args.server_name, 
                args.routing_zone,
                args.os_vn,
                args.business_vn,
                auto_complete=args.auto_complete
            )
        
        logger.info("Script completed successfully!")
        
    except Exception as e:
        logger.error(f"Script failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()