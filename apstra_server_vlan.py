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
# Create a custom logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create file handler for detailed logging
file_handler = logging.FileHandler('apstra_server_vlan.log')
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)

# Create console handler for user-facing output (warnings and errors only by default)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.WARNING)
console_formatter = logging.Formatter('%(message)s')
console_handler.setFormatter(console_formatter)

# Add handlers to logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Configure httpx logging to only go to file
httpx_logger = logging.getLogger("httpx")
httpx_logger.setLevel(logging.WARNING)
httpx_logger.addHandler(file_handler)
httpx_logger.propagate = False

# User-facing output functions
def print_step(step_num: int, description: str):
    """Print a step to the console with clear formatting"""
    print(f"\n🔧 Step {step_num}: {description}")

def print_info(message: str):
    """Print an info message to the console"""
    print(f"ℹ️  {message}")

def print_success(message: str):
    """Print a success message to the console"""
    print(f"✅ {message}")

def print_warning(message: str):
    """Print a warning message to the console"""
    print(f"⚠️  {message}")

def print_error(message: str):
    """Print an error message to the console"""
    print(f"❌ {message}")

def ask_consent(action: str, details: str = "") -> bool:
    """Ask user for consent before performing an action"""
    print(f"\n⚠️  About to: {action}")
    if details:
        print(f"   Details: {details}")
    
    while True:
        response = input("   Do you want to proceed? (y/n): ").strip().lower()
        if response in ['y', 'yes']:
            return True
        elif response in ['n', 'no']:
            return False
        else:
            print("   Please enter 'y' for yes or 'n' for no.")

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
    interface_names: List[str]  # Actually contains interface descriptions: "server_if <-> switch:switch_if"

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
            
            # Handle HTTP 204 No Content response (successful but no body)
            if response.status_code == 204:
                return {"status": "success", "message": "LAG mode changed successfully"}
            
            # Try to parse JSON, but handle empty responses
            try:
                return response.json()
            except Exception:
                return {"status": "success", "message": "LAG mode changed successfully"}
            
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
            
            # Handle HTTP 204 No Content response (successful but no body)
            if response.status_code == 204:
                return {"status": "success", "message": f"Interface {interface_id} set to {state} successfully"}
            
            # Try to parse JSON, but handle empty responses
            try:
                return response.json()
            except Exception:
                return {"status": "success", "message": f"Interface {interface_id} set to {state} successfully"}
            
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
            
            # Handle HTTP 204 No Content response (successful but no body)
            if response.status_code == 204:
                return {"status": "success", "message": f"Policy {policy_id} {action} successfully"}
            
            # Try to parse JSON, but handle empty responses
            try:
                return response.json()
            except Exception:
                return {"status": "success", "message": f"Policy {policy_id} {action} successfully"}
            
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
            
            # Handle HTTP 204 No Content response (successful but no body)
            if response.status_code == 204:
                return {"status": "success", "message": f"Configuration deployed: {description}"}
            
            # Try to parse JSON, but handle empty responses
            try:
                return response.json()
            except Exception:
                return {"status": "success", "message": f"Configuration deployed: {description}"}
            
        except Exception as e:
            logger.error(f"Failed to deploy configuration: {e}")
            raise

class ServerUpgradeManager:
    """Main class to manage server OS upgrade process"""
    
    def __init__(self, apstra_client: ApstraClient, auto_yes: bool = False):
        self.client = apstra_client
        self.server_config: Optional[ServerConfig] = None
        self.phase = UpgradePhase.INIT
        self.policies = {}
        self.application_points = {}
        self.auto_yes = auto_yes
        
    def discover_server(self, server_name: str) -> ServerConfig:
        """Discover server configuration from Apstra"""
        logger.info(f"Discovering server configuration for: {server_name}")
        
        # Get system info
        system_info = self.client.get_system_info()
        
        # Find the server
        server_data = None
        for system in system_info.get('data', []):
            label = system.get('label', '')
            hostname = system.get('hostname', '') or ''  # Handle None hostnames
            if (label.lower() == server_name.lower() or 
                hostname.lower() == server_name.lower()):
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
        interface_descriptions = []
        
        for link in cabling_map.get('links', []):
            if link.get('role') == 'to_generic' and 'dual-link' in link.get('group_label', ''):
                # Check if this link involves our server
                server_endpoint = None
                switch_endpoint = None
                
                for endpoint in link.get('endpoints', []):
                    if endpoint['system']['id'] == server_data['id']:
                        server_endpoint = endpoint
                    else:
                        switch_endpoint = endpoint
                
                if server_endpoint and switch_endpoint:
                    lag_connections.append(link)
                    # Store switch interface ID for configuration
                    interface_ids.append(switch_endpoint['interface']['id'])
                    
                    # Create comprehensive interface description
                    server_interface = server_endpoint['interface'].get('if_name', server_endpoint['interface'].get('name', 'Unknown'))
                    switch_interface = switch_endpoint['interface'].get('if_name', switch_endpoint['interface'].get('name', 'Unknown'))
                    switch_name = switch_endpoint['system'].get('label', 'Unknown')
                    
                    interface_desc = f"{server_interface} <-> {switch_name}:{switch_interface}"
                    interface_descriptions.append(interface_desc)
        
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
            interface_ids=interface_ids,
            interface_names=interface_descriptions
        )
    
    def discover_network_policies(self, routing_zone: str, os_vn_name: str = None, business_vn_name: str = None) -> Tuple[str, str, str, str, str]:
        """Discover virtual network policies and application points"""
        vn_names = []
        if os_vn_name:
            vn_names.append(f"OS VN '{os_vn_name}'")
        if business_vn_name:
            vn_names.append(f"Business VN '{business_vn_name}'")
        
        logger.info(f"Discovering policies for routing zone '{routing_zone}'" + (f", {', '.join(vn_names)}" if vn_names else ""))
        
        # Get routing zones to validate the specified routing zone exists
        rz_response = self.client.get_routing_zones()
        logger.info(f"Routing zones response type: {type(rz_response)}")
        
        # Parse routing zones response - it has an 'items' key
        rz_data = rz_response
        if isinstance(rz_response, dict) and 'items' in rz_response:
            rz_data = rz_response['items']
        
        routing_zone_id = None
        available_rz = []
        
        if isinstance(rz_data, dict):
            for rz_id, rz_info in rz_data.items():
                if isinstance(rz_info, dict):
                    rz_label = rz_info.get('label', rz_info.get('name', 'Unknown'))
                    available_rz.append(rz_label)
                    if rz_label == routing_zone:
                        routing_zone_id = rz_id
                        logger.info(f"Found routing zone '{routing_zone}' with ID: {routing_zone_id}")
                        break
        
        logger.info(f"Available routing zones: {available_rz}")
        
        if not routing_zone_id:
            raise ValueError(f"Routing zone '{routing_zone}' not found. Available routing zones: {available_rz}")
        
        # Get virtual networks
        vn_response = self.client.get_virtual_networks()
        logger.info(f"Virtual networks response type: {type(vn_response)}")
        
        # Parse virtual networks response - has a 'virtual_networks' key
        vn_data = vn_response
        if isinstance(vn_response, dict) and 'virtual_networks' in vn_response:
            vn_data = vn_response['virtual_networks']
        
        os_vn_id = None
        business_vn_id = None
        available_vns = []
        
        if isinstance(vn_data, dict):
            for vn_id, vn_info in vn_data.items():
                if isinstance(vn_info, dict):
                    vn_label = vn_info.get('label', vn_info.get('name', 'Unknown'))
                    vn_security_zone = vn_info.get('security_zone_id', '')
                    available_vns.append(f"{vn_label} (zone: {vn_security_zone})")
                    
                    # Check if this VN is in our routing zone and matches our names
                    if vn_security_zone == routing_zone_id:
                        if os_vn_name and vn_label == os_vn_name:
                            os_vn_id = vn_id
                            logger.info(f"Found OS virtual network '{os_vn_name}' with ID: {os_vn_id}")
                        elif business_vn_name and vn_label == business_vn_name:
                            business_vn_id = vn_id
                            logger.info(f"Found business virtual network '{business_vn_name}' with ID: {business_vn_id}")
        
        logger.info(f"Available virtual networks: {available_vns}")
        
        # Validate that requested virtual networks were found
        if os_vn_name and not os_vn_id:
            raise ValueError(f"OS virtual network '{os_vn_name}' not found in routing zone '{routing_zone}'. Available VNs: {available_vns}")
        if business_vn_name and not business_vn_id:
            raise ValueError(f"Business virtual network '{business_vn_name}' not found in routing zone '{routing_zone}'. Available VNs: {available_vns}")
        
        # Get connectivity templates to find policies for these virtual networks
        ct_response = self.client.get_connectivity_templates()
        logger.info(f"Connectivity templates response type: {type(ct_response)}")
        
        os_policy_id = None
        business_policy_id = None
        available_policies = []
        
        # Parse connectivity templates - response has 'policies' key with list of policies
        policies = ct_response.get('policies', []) if isinstance(ct_response, dict) else []
        
        # Create a map of all policies by ID for easy lookup
        policy_map = {p.get('id'): p for p in policies if isinstance(p, dict)}
        
        # Look for visible batch policies and trace their VN associations
        os_policy_label = None
        business_policy_label = None
        
        for policy in policies:
            if isinstance(policy, dict) and policy.get('visible', False) and policy.get('policy_type_name') == 'batch':
                policy_id = policy.get('id')
                policy_label = policy.get('label', '')
                available_policies.append(f"{policy_label} (ID: {policy_id})")
                
                # Trace the policy hierarchy to find the VN association
                vn_node_id = self._trace_policy_vn_association(policy, policy_map)
                
                if os_vn_id and vn_node_id == os_vn_id:
                    os_policy_id = policy_id
                    os_policy_label = policy_label
                    logger.info(f"Found OS policy ID: {os_policy_id} for VN '{os_vn_name}' (VN ID: {os_vn_id})")
                elif business_vn_id and vn_node_id == business_vn_id:
                    business_policy_id = policy_id
                    business_policy_label = policy_label
                    logger.info(f"Found business policy ID: {business_policy_id} for VN '{business_vn_name}' (VN ID: {business_vn_id})")
        
        # Get application endpoints
        app_endpoints_response = self.client.get_application_endpoints()
        logger.info(f"Application endpoints response type: {type(app_endpoints_response)}")
        
        # Parse the response - it has 'application_points' key
        if isinstance(app_endpoints_response, dict):
            app_endpoints = app_endpoints_response.get('application_points', app_endpoints_response)
        else:
            app_endpoints = app_endpoints_response
        
        # Find application point for our server by traversing the hierarchical tree
        server_app_point_id = None
        if isinstance(app_endpoints, dict):
            server_app_point_id = self._find_server_application_point(
                app_endpoints, self.server_config.server_name if self.server_config else ""
            )
        
        # Validate that required policies were found
        logger.info(f"Available policies: {available_policies}")
        
        if os_vn_name and not os_policy_id:
            raise ValueError(f"OS virtual network '{os_vn_name}' connectivity template not found. Available policies: {available_policies}")
        if business_vn_name and not business_policy_id:
            raise ValueError(f"Business virtual network '{business_vn_name}' connectivity template not found. Available policies: {available_policies}")
        if not server_app_point_id:
            raise ValueError("Server application point not found. Cannot proceed with upgrade.")
        
        return os_policy_id, business_policy_id, server_app_point_id, os_policy_label, business_policy_label
    
    def _trace_policy_vn_association(self, policy: Dict, policy_map: Dict) -> Optional[str]:
        """Trace policy hierarchy to find the associated vn_node_id"""
        if not isinstance(policy, dict):
            return None
        
        # Check if this policy directly has vn_node_id
        attributes = policy.get('attributes', {})
        if isinstance(attributes, dict) and 'vn_node_id' in attributes:
            return attributes['vn_node_id']
        
        # For batch policies, follow subpolicies
        if policy.get('policy_type_name') == 'batch' and 'subpolicies' in attributes:
            subpolicy_ids = attributes.get('subpolicies', [])
            for subpolicy_id in subpolicy_ids:
                subpolicy = policy_map.get(subpolicy_id)
                if subpolicy:
                    vn_node_id = self._trace_policy_vn_association(subpolicy, policy_map)
                    if vn_node_id:
                        return vn_node_id
        
        # For pipeline policies, follow first_subpolicy
        if policy.get('policy_type_name') == 'pipeline' and 'first_subpolicy' in attributes:
            first_subpolicy_id = attributes.get('first_subpolicy')
            if first_subpolicy_id:
                first_subpolicy = policy_map.get(first_subpolicy_id)
                if first_subpolicy:
                    return self._trace_policy_vn_association(first_subpolicy, policy_map)
        
        return None
    
    def _find_server_application_point(self, app_endpoints: Dict, server_name: str) -> Optional[str]:
        """Find application point for server by traversing the hierarchical tree"""
        self.server_interface_label = None  # Store for user-friendly display
        
        def traverse_children(children_list):
            """Recursively traverse children to find server interface"""
            if not isinstance(children_list, list):
                return None
            
            for child in children_list:
                if not isinstance(child, dict):
                    continue
                
                child_label = child.get('label', '')
                child_id = child.get('id', '')
                child_type = child.get('type', '')
                
                # Check if this is an interface referencing our server
                if child_type == 'interface' and server_name in child_label:
                    logger.info(f"Found server application point: {child_label} (ID: {child_id})")
                    self.server_interface_label = child_label  # Store for display
                    return child_id
                
                # Recursively check children
                grandchildren = child.get('children', [])
                if grandchildren:
                    result = traverse_children(grandchildren)
                    if result:
                        return result
            
            return None
        
        # Start traversal from the root children
        root_children = app_endpoints.get('children', [])
        return traverse_children(root_children)
    
    def pre_upgrade_phase(self) -> None:
        """Execute pre-upgrade phase"""
        print("\n" + "="*60)
        print("🚀 STARTING PRE-UPGRADE PHASE")
        print("="*60)
        logger.info("=== Starting Pre-Upgrade Phase ===")
        self.phase = UpgradePhase.PRE_UPGRADE
        
        if not self.server_config:
            raise ValueError("Server configuration not initialized")
        
        # Validate that required policies are available before proceeding
        if not self.policies.get('os_policy_id'):
            raise ValueError(f"OS virtual network '{self.server_config.os_virtual_network}' policy not found. Cannot proceed with upgrade.")
        
        if not self.application_points.get('server_app_point_id'):
            raise ValueError("Server application point not found. Cannot proceed with upgrade.")
        
        try:
            # Step 1: Select and disable interfaces for redundancy during upgrade
            print_step(1, "Selecting and disabling interfaces for redundancy during upgrade")
            
            # Show all available interfaces
            print_info("Available interface connections:")
            for i, interface_desc in enumerate(self.server_config.interface_names):
                print(f"    {i+1}. {interface_desc}")
            
            # Let user choose which interfaces to disable (or use default for auto mode)
            if self.auto_yes:
                # Default: disable every second interface for redundancy
                interfaces_to_disable_indices = list(range(1, len(self.server_config.interface_ids), 2))
                print_info(f"Auto mode: selecting interfaces {[i+1 for i in interfaces_to_disable_indices]} for disable")
            else:
                # Interactive mode: let user choose
                print_info("Select which interface(s) to disable during OS upgrade (for redundancy):")
                print_info("Enter interface numbers separated by commas (e.g., 2,4) or 'default' for automatic selection:")
                
                while True:
                    user_input = input("   Interface selection: ").strip()
                    if user_input.lower() == 'default':
                        interfaces_to_disable_indices = list(range(1, len(self.server_config.interface_ids), 2))
                        break
                    else:
                        try:
                            selected = [int(x.strip())-1 for x in user_input.split(',')]
                            if all(0 <= i < len(self.server_config.interface_ids) for i in selected):
                                interfaces_to_disable_indices = selected
                                break
                            else:
                                print("   Invalid selection. Please enter valid interface numbers.")
                        except ValueError:
                            print("   Invalid input. Please enter numbers separated by commas or 'default'.")
            
            # Get the selected interfaces to disable
            interfaces_to_disable = [self.server_config.interface_ids[i] for i in interfaces_to_disable_indices]
            interface_names_to_disable = [self.server_config.interface_names[i] for i in interfaces_to_disable_indices]
            
            details = f"Will disable the following connection(s) for redundancy during OS upgrade:\\n    " + "\\n    ".join(interface_names_to_disable)
            
            if self.auto_yes or ask_consent("Disable selected interfaces", details):
                for interface_id in interfaces_to_disable:
                    self.client.set_interface_state(interface_id, "admin_down")
                print_success(f"Successfully disabled {len(interface_names_to_disable)} interface connection(s)")
                logger.info("Step 1: Disabling selected interfaces for redundancy - completed")
            else:
                print_warning("Operation cancelled by user")
                return
            
            # Step 2: Convert LACP active LAGs to static LAGs
            print_step(2, "Converting LACP active LAGs to static LAGs")
            link_ids = [link['id'] for link in self.server_config.lag_connections]
            
            print_info("LAG links to be converted:")
            for i, interface_desc in enumerate(self.server_config.interface_names, 1):
                link_id = link_ids[i-1] if i-1 < len(link_ids) else "Unknown"
                print(f"      {i}. {interface_desc} (Link ID: {link_id})")
            
            details = f"Will change {len(link_ids)} LAG connections from LACP active to static mode for server '{self.server_config.server_name}'"
            
            if self.auto_yes or ask_consent("Convert LACP LAGs to static LAGs", details):
                self.client.change_lag_mode(link_ids, "static_lag")
                print_success(f"Successfully converted {len(link_ids)} LAG connections to static mode")
                logger.info("Step 2: Converting LACP active LAGs to static LAGs - completed")
            else:
                print_warning("Operation cancelled by user")
                return
            
            # Step 3: Apply OS virtual network policy
            print_step(3, f"Assigning server to OS virtual network '{self.server_config.os_virtual_network}'")
            
            # Show application endpoint interface details
            if hasattr(self, 'server_interface_label') and self.server_interface_label:
                print_info("Application endpoint interface:")
                print(f"      Interface: {self.server_interface_label}")
            
            details = f"Will assign server '{self.server_config.server_name}' to OS upgrade virtual network '{self.server_config.os_virtual_network}' for maintenance"
            
            if self.policies.get('os_policy_id') and self.application_points.get('server_app_point_id'):
                if self.auto_yes or ask_consent("Assign OS virtual network", details):
                    self.client.apply_vlan_policy(
                        self.application_points['server_app_point_id'],
                        self.policies['os_policy_id'],
                        apply=True
                    )
                    print_success(f"Successfully assigned server to OS virtual network '{self.server_config.os_virtual_network}'")
                    logger.info(f"Step 3: Assigning server to OS virtual network '{self.server_config.os_virtual_network}' - completed")
                else:
                    print_warning("Operation cancelled by user")
                    return
            else:
                print_warning("Skipping virtual network assignment - policies not discovered")
            
            # Step 4: Deploy configuration
            print_step(4, "Deploying pre-upgrade configuration to network devices")
            details = f"Will deploy all interface, LAG and virtual network configuration changes for server '{self.server_config.server_name}' to the network infrastructure"
            
            if self.auto_yes or ask_consent("Deploy configuration changes", details):
                self.client.deploy_configuration("Pre-upgrade: Disable interfaces, convert to static LAG and assign OS VLAN")
                print_success("Successfully deployed pre-upgrade configuration")
                logger.info("Step 4: Deploying pre-upgrade configuration - completed")
            else:
                print_warning("Operation cancelled by user")
                return
            
            print("\n" + "="*60)
            print("✅ PRE-UPGRADE PHASE COMPLETED SUCCESSFULLY")
            print("="*60)
            print_info("Server is now ready for OS upgrade")
            print_info("Run the script again with --post-upgrade flag after OS upgrade is complete")
            logger.info("=== Pre-Upgrade Phase Completed ===")
            
        except Exception as e:
            self.phase = UpgradePhase.FAILED
            print_error(f"Pre-upgrade phase failed: {e}")
            logger.error(f"Pre-upgrade phase failed: {e}")
            raise
    
    def post_upgrade_phase(self) -> None:
        """Execute post-upgrade phase"""
        print("\n" + "="*60)
        print("🔄 STARTING POST-UPGRADE PHASE")
        print("="*60)
        logger.info("=== Starting Post-Upgrade Phase ===")
        self.phase = UpgradePhase.POST_UPGRADE
        
        if not self.server_config:
            raise ValueError("Server configuration not initialized")
        
        # Validate that required policies are available for post-upgrade
        if not self.policies.get('os_policy_id'):
            raise ValueError(f"OS virtual network '{self.server_config.os_virtual_network}' policy not found. Cannot remove OS assignment.")
        if not self.policies.get('business_policy_id'):
            raise ValueError(f"Business virtual network '{self.server_config.business_virtual_network}' policy not found. Cannot proceed with post-upgrade.")
        
        try:
            # Step 1: Re-enable previously disabled interfaces  
            print_step(1, "Re-enabling previously disabled interfaces")
            
            # For post-upgrade, we assume the same interfaces that were disabled during pre-upgrade
            # In a production scenario, this info should be stored/retrieved from the pre-upgrade phase
            interfaces_to_enable = self.server_config.interface_ids[1::2]  # Default pattern
            interface_names_to_enable = self.server_config.interface_names[1::2]  # Default pattern
            
            print_info("Previously disabled interface connections:")
            for interface_desc in interface_names_to_enable:
                print(f"    • {interface_desc}")
            
            details = f"Will re-enable the above connection(s) to restore full redundancy"
            
            if self.auto_yes or ask_consent("Re-enable disabled interfaces", details):
                for interface_id in interfaces_to_enable:
                    self.client.set_interface_state(interface_id, "up")
                print_success(f"Successfully re-enabled {len(interface_names_to_enable)} interface connection(s)")
                logger.info("Step 1: Re-enabling previously disabled interfaces - completed")
            else:
                print_warning("Operation cancelled by user")
                return
            
            # Step 2: Convert static LAGs back to LACP active
            print_step(2, "Converting static LAGs back to LACP active")
            link_ids = [link['id'] for link in self.server_config.lag_connections]
            
            print_info("LAG links to be converted:")
            for i, interface_desc in enumerate(self.server_config.interface_names, 1):
                link_id = link_ids[i-1] if i-1 < len(link_ids) else "Unknown"
                print(f"      {i}. {interface_desc} (Link ID: {link_id})")
            
            details = f"Will convert {len(link_ids)} LAG connections on server '{self.server_config.server_name}' back to LACP active mode"
            
            if self.auto_yes or ask_consent("Convert static LAGs back to LACP", details):
                self.client.change_lag_mode(link_ids, "lacp_active")
                print_success(f"Successfully converted {len(link_ids)} LAG connections to LACP active")
                logger.info("Step 2: Converting static LAGs back to LACP active - completed")
            else:
                print_warning("Operation cancelled by user")
                return
            
            # Step 3: Remove OS virtual network policy
            print_step(3, f"Removing OS virtual network assignment")
            
            # Show application endpoint interface details
            if hasattr(self, 'server_interface_label') and self.server_interface_label:
                print_info("Application endpoint interface:")
                print(f"      Interface: {self.server_interface_label}")
            
            details = f"Will remove server '{self.server_config.server_name}' from OS upgrade network (maintenance mode)"
            
            if self.policies.get('os_policy_id') and self.application_points.get('server_app_point_id'):
                if self.auto_yes or ask_consent("Remove OS virtual network assignment", details):
                    self.client.apply_vlan_policy(
                        self.application_points['server_app_point_id'],
                        self.policies['os_policy_id'],
                        apply=False
                    )
                    print_success(f"Successfully removed OS virtual network '{self.server_config.os_virtual_network}' assignment")
                    logger.info(f"Step 3: Removing OS virtual network '{self.server_config.os_virtual_network}' assignment - completed")
                else:
                    print_warning("Operation cancelled by user")
                    return
            else:
                print_warning("Skipping OS virtual network removal - policies not discovered")
            
            # Step 4: Apply business virtual network policy
            print_step(4, f"Assigning server to business virtual network '{self.server_config.business_virtual_network}'")
            
            # Show application endpoint interface details
            if hasattr(self, 'server_interface_label') and self.server_interface_label:
                print_info("Application endpoint interface:")
                print(f"      Interface: {self.server_interface_label}")
            
            details = f"Will assign server '{self.server_config.server_name}' to production business virtual network '{self.server_config.business_virtual_network}'"
            
            if self.policies.get('business_policy_id') and self.application_points.get('server_app_point_id'):
                if self.auto_yes or ask_consent("Assign business virtual network", details):
                    self.client.apply_vlan_policy(
                        self.application_points['server_app_point_id'],
                        self.policies['business_policy_id'],
                        apply=True
                    )
                    print_success(f"Successfully assigned server to business virtual network '{self.server_config.business_virtual_network}'")
                    logger.info(f"Step 4: Assigning server to business virtual network '{self.server_config.business_virtual_network}' - completed")
                else:
                    print_warning("Operation cancelled by user")
                    return
            else:
                print_warning("Skipping business virtual network assignment - policies not discovered")
            
            # Step 5: Deploy final configuration
            print_step(5, "Deploying final post-upgrade configuration")
            details = f"Will deploy all final LAG and virtual network configuration changes for server '{self.server_config.server_name}' to complete the upgrade"
            
            if self.auto_yes or ask_consent("Deploy final configuration", details):
                self.client.deploy_configuration("Post-upgrade: Restore LACP and assign business VLAN")
                print_success("Successfully deployed post-upgrade configuration")
                logger.info("Step 5: Deploying post-upgrade configuration - completed")
            else:
                print_warning("Operation cancelled by user")
                return
            
            self.phase = UpgradePhase.COMPLETE
            print("\n" + "="*60)
            print("🎉 POST-UPGRADE PHASE COMPLETED SUCCESSFULLY")
            print("="*60)
            print_info("Server upgrade workflow completed successfully!")
            print_info("Server is now running on upgraded OS with production network configuration")
            logger.info("=== Post-Upgrade Phase Completed ===")
            
        except Exception as e:
            self.phase = UpgradePhase.FAILED
            print_error(f"Post-upgrade phase failed: {e}")
            logger.error(f"Post-upgrade phase failed: {e}")
            raise
    
    def run_upgrade(self, server_name: str, routing_zone: str, os_vn_name: str, business_vn_name: str = None, 
                   auto_complete: bool = False) -> None:
        """Run the complete upgrade process"""
        try:
            # Initialize
            print("\n" + "="*60)
            print("🔍 INITIALIZING SERVER OS UPGRADE")
            print("="*60)
            print_info(f"Server: {server_name}")
            print_info(f"Routing Zone: {routing_zone}")
            print_info(f"OS Virtual Network: {os_vn_name}")
            if business_vn_name:
                print_info(f"Business Virtual Network: {business_vn_name}")
            
            logger.info(f"Starting server OS upgrade for: {server_name}")
            if business_vn_name:
                logger.info(f"Routing zone: {routing_zone}, OS VN: {os_vn_name}, Business VN: {business_vn_name}")
            else:
                logger.info(f"Routing zone: {routing_zone}, OS VN: {os_vn_name}")
            
            # Discover server
            print_info("Discovering server configuration...")
            self.server_config = self.discover_server(server_name)
            self.server_config.routing_zone = routing_zone
            self.server_config.os_virtual_network = os_vn_name
            self.server_config.business_virtual_network = business_vn_name or ""
            print_success(f"Found server '{self.server_config.server_name}' with {len(self.server_config.lag_connections)} LAG connections")
            
            # Discover policies
            print_info("Discovering network policies and application points...")
            os_policy_id, business_policy_id, server_app_point_id, os_policy_label, business_policy_label = self.discover_network_policies(
                routing_zone, os_vn_name, business_vn_name
            )
            
            self.policies = {
                'os_policy_id': os_policy_id,
                'business_policy_id': business_policy_id,
                'os_policy_label': os_policy_label,
                'business_policy_label': business_policy_label
            }
            self.application_points = {
                'server_app_point_id': server_app_point_id
            }
            
            # Show what was discovered
            if os_policy_id:
                print_success(f"Found OS policy: {os_policy_label} (ID: {os_policy_id})")
            if business_policy_id:
                print_success(f"Found Business policy: {business_policy_label} (ID: {business_policy_id})")
            interface_label = getattr(self, 'server_interface_label', None)
            if interface_label:
                print_success(f"Found application point: {interface_label} (ID: {server_app_point_id})")
            else:
                print_success(f"Found application point for server '{self.server_config.server_name}' (ID: {server_app_point_id})")
            
            # Execute pre-upgrade phase
            self.pre_upgrade_phase()
            
            if auto_complete:
                print_info("Auto-complete mode: Proceeding directly to post-upgrade phase")
                self.post_upgrade_phase()
        
        except Exception as e:
            print_error(f"Upgrade process failed: {e}")
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
    # Check if dry-run is specified to determine if --os-vn should be required
    import sys
    is_dry_run = '--dry-run' in sys.argv
    
    parser.add_argument('--os-vn', '-os', required=not is_dry_run,
                       help='OS upgrade virtual network name (required for both pre-upgrade and post-upgrade)')
    parser.add_argument('--business-vn', '-bvn',
                       help='Business virtual network name (required for post-upgrade). Note: --bvn is a shortcut for --business-vn')
    
    # Optional arguments
    parser.add_argument('--config', '-c', default='apstra_config.json',
                       help='Apstra configuration file (default: apstra_config.json)')
    parser.add_argument('--post-upgrade', action='store_true',
                       help='Run only post-upgrade phase (after OS upgrade is complete)')
    parser.add_argument('--auto-complete', action='store_true',
                       help='Automatically run both pre and post upgrade phases')
    parser.add_argument('--dry-run', action='store_true',
                       help='Dry run mode - discover configuration but make no changes')
    parser.add_argument('--yes', '-y', action='store_true',
                       help='Automatically answer yes to all prompts (non-interactive mode)')
    
    args = parser.parse_args()
    
    # Validate argument combinations
    if args.post_upgrade and not args.business_vn:
        parser.error("--business-vn is required when using --post-upgrade. Note: --bvn is a shortcut for --business-vn")
    
    # Check if OS-VN and Business-VN are the same (both provided and identical)
    if args.os_vn and args.business_vn and args.os_vn == args.business_vn:
        print_error(f"OS VN and Business VN cannot be the same (both set to '{args.os_vn}'). Use different virtual networks.")
        sys.exit(1)
    
    try:
        # Load configuration
        apstra_config = load_config(args.config, args.blueprint_name)
        
        # Create client
        client = ApstraClient(apstra_config)
        
        # Create upgrade manager
        upgrade_manager = ServerUpgradeManager(client, auto_yes=args.yes)
        
        if args.dry_run:
            print("\n" + "="*60)
            print("🧪 DRY RUN MODE - NO CHANGES WILL BE MADE")
            print("="*60)
            
            server_config = upgrade_manager.discover_server(args.server_name)
            server_config.routing_zone = args.routing_zone
            server_config.os_virtual_network = args.os_vn or ""
            server_config.business_virtual_network = args.business_vn or ""
            
            print_info("Server Configuration:")
            print(f"    Server: {server_config.server_name} (ID: {server_config.server_id})")
            print(f"    LAG Connections: {len(server_config.lag_connections)}")
            print(f"    Interface Connections:")
            for i, interface_desc in enumerate(server_config.interface_names, 1):
                print(f"      {i}. {interface_desc}")
            print(f"    Routing Zone: {server_config.routing_zone}")
            if args.os_vn:
                print(f"    OS Virtual Network: {server_config.os_virtual_network}")
            if args.business_vn:
                print(f"    Business Virtual Network: {server_config.business_virtual_network}")
            
            os_policy, business_policy, app_point, os_policy_label, business_policy_label = upgrade_manager.discover_network_policies(
                args.routing_zone, args.os_vn, args.business_vn
            )
            print_info("Network Policies:")
            if args.os_vn and os_policy_label:
                print(f"    OS Policy: {os_policy_label} (ID: {os_policy})")
            if args.business_vn and business_policy_label:
                print(f"    Business Policy: {business_policy_label} (ID: {business_policy})")
            interface_label = getattr(upgrade_manager, 'server_interface_label', None)
            if interface_label:
                print(f"    Application Point: {interface_label} (ID: {app_point})")
            else:
                print(f"    Application Point: Found for server (ID: {app_point})")
            
            print_success("Dry run completed - all required components discovered")
            
        elif args.post_upgrade:
            print_info("Running POST-UPGRADE phase only")
            upgrade_manager.server_config = upgrade_manager.discover_server(args.server_name)
            upgrade_manager.server_config.routing_zone = args.routing_zone
            upgrade_manager.server_config.os_virtual_network = args.os_vn  # Needed to remove OS assignment
            upgrade_manager.server_config.business_virtual_network = args.business_vn
            
            os_policy_id, business_policy_id, server_app_point_id, os_policy_label, business_policy_label = upgrade_manager.discover_network_policies(
                args.routing_zone, args.os_vn, args.business_vn  # Need both OS VN (to remove) and business VN (to assign)
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
                args.business_vn,  # May be None for pre-upgrade only
                auto_complete=args.auto_complete
            )
        
        print_success("Script completed successfully!")
        logger.info("Script completed successfully!")
        
    except Exception as e:
        logger.error(f"Script failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()