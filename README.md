# Apstra Server VLAN Management Script

This Python script automates sserver LAG and VLAN management in Juniper Apstra (DC Director) environments. It has been written for a special Method-of-Procedure that requires the steps mentioned in the following section.

## Overview

The script manages the complete workflow for upgrading a server's operating system while maintaining network connectivity:

1. **Pre-Upgrade Phase:**
   - Disable one of the LAG member interfaces
   - Convert LACP active LAGs to static LAGs
   - Assign server to OS upgrade VLAN
   - Deploy configuration

2. **OS Upgrade Phase:** (Manual - performed by user)
   - Server OS upgrade is performed externally

3. **Post-Upgrade Phase:**
   - Re-enable disabled LAG members
   - Convert static LAGs back to LACP active
   - Remove OS upgrade VLAN assignment
   - Assign server to business VLAN
   - Deploy final configuration

## Requirements

- Python 3.7+
- `httpx` library for HTTP requests
- Access to Juniper Apstra system

## Installation

1. Install required dependencies:
```bash
pip install httpx
```

2. Copy the script and configuration files to your working directory

3. Create your Apstra configuration file based on `apstra_config_sample.json`

## Configuration

### Apstra Configuration File

Create `apstra_config.json` with your Apstra system details:

```json
{
  "server": "your-apstra-server.com",
  "port": "443",
  "username": "your_username",
  "password": "your_password",
  "blueprint_name": "your-blueprint-name"
}
```

### Server Requirements

The script expects the following configuration:
- Server must exist in the Apstra blueprint
- LAG setup (connected to a leaf pair in the Apstra-managed DC fabric)
- Server interfaces configured with LACP active
- The following artifacts must already exist in Apstra:
   - Blueprint
   - Security zone
   - Virtual networks and their corresponding connectivity templates for both OS upgrade and business VLANs

## Usage

### Basic Usage

Pre-upgrade:
```bash
python apstra_server_vlan.py --server-name "server001" --blueprint-name "datacenter-blueprint" --os-vlan 2000
```

Post-upgrade:
```bash
python apstra_server_vlan.py --server-name "server001" --blueprint-name "datacenter-blueprint" --os-vlan 2000 --business-vlan 100 --post-upgrade
```

### Command Line Options

```bash
Required Arguments:
  --server-name, -s      Server name/label to upgrade
  --os-vlan, -o         Virtual network for OS upgrade
  --business-vlan, -b   Virtual network for Business VLAN

Optional Arguments:
  --blueprint-name, -bp Blueprint name (can also be in config file)
  --config, -c          Apstra configuration file (default: apstra_config.json)
  --post-upgrade        Run only post-upgrade phase (after OS upgrade is complete)
  --auto-complete       Automatically run both pre and post upgrade phases
  --dry-run            Dry run mode - discover configuration but make no changes
```

### Workflow Examples

#### 1. Standard Two-Phase Approach (Recommended)

**Step 1: Pre-Upgrade**
```bash
python apstra_server_vlan.py -s "server001" -bp "datacenter-blueprint" -o 2000 -b 100
```

**Step 2: Perform OS Upgrade** (not handled by the script)

**Step 3: Post-Upgrade**
```bash
python apstra_server_vlan.py -s "server001" -bp "datacenter-blueprint" -o 2000 -b 100 --post-upgrade
```

#### 2. Dry Run (Discovery Only)
```bash
python apstra_server_vlan.py -s "server001" -bp "datacenter-blueprint" -o 2000 -b 100 --dry-run
```

#### 3. Auto-Complete (Testing Only)
```bash
python apstra_server_vlan.py -s "server001" -bp "datacenter-blueprint" -o 2000 -b 100 --auto-complete
```

## Script Features

### Automatic Discovery
- Server configuration and LAG connections
- Interface IDs for LAG members
- VLAN policies and application points
- Blueprint topology information

### Error Handling
- Comprehensive logging to file and console
- Graceful error recovery
- Detailed error messages

### Safety Features
- Dry-run mode for testing
- Configuration validation
- Phase-based execution
- Deployment status tracking

## Logging

The script creates detailed logs in `apstra_server_vlan.log` including:
- All API calls and responses
- Configuration changes
- Error details
- Timing information

## Example Usage

Based on the provided JSON data, here's an example using the discovered server:

```bash
# Dry run to verify configuration
python apstra_server_vlan.py -s "server001" -bp "datacenter-blueprint" -o 2000 -b 300 --dry-run

# Pre-upgrade phase
python apstra_server_vlan.py -s "server001" -bp "datacenter-blueprint" -o 2000

# [Perform OS upgrade manually]

# Post-upgrade phase
python apstra_server_vlan.py -s "server001" -bp "datacenter-blueprint" -o 2000 -b 300 --post-upgrade
```

## Network Topology

The script handles servers with this topology:
```
Server (server001)
├── eth0 ──(LAG1)── leaf1:ge-0/0/2
└── eth1 ──(LAG1)── leaf2:ge-0/0/2
```

## Troubleshooting

### Common Issues

1. **Authentication Failed**
   - Verify credentials in config file
   - Check server URL and port

2. **Server Not Found**
   - Verify server name/label
   - Check blueprint ID
   - Ensure server exists in blueprint

3. **No LAG Connections Found**
   - Verify server has dual-link configuration
   - Check cabling map data

4. **Policy Discovery Failed**
   - VLAN policies may need manual specification
   - Check connectivity templates configuration

### Debug Mode

Enable detailed logging by modifying the log level:
```python
logging.basicConfig(level=logging.DEBUG)
```

## Security Considerations

- Store credentials securely
- Use environment variables for sensitive data
- Enable HTTPS verification in production
- Restrict script access to authorized personnel

## Contributing

For improvements or bug reports, please provide:
- Script version and Python version
- Complete error logs
- Network topology details
- Apstra version information
