# Apstra Server VLAN Management Script

This Python script automates server LAG and VLAN management in Juniper Apstra (DC Director) environments. It has been written for a special Method-of-Procedure that requires the steps mentioned in the following section.

## Overview

The script manages the complete workflow for upgrading a server's operating system while maintaining network connectivity:

1. **Pre-Upgrade Phase:**
   - Disable selected LAG member interfaces during OS upgrade process
   - Change LACP mode for the LAG interfaces from LACP active to static LAG
   - Assign server LAG interfaces to OS upgrade virtual network
   - Deploy configuration

2. **OS Upgrade Phase:** (Manual - performed by user)
   - Server OS upgrade is performed externally

3. **Post-Upgrade Phase:**
   - Re-enable previously disabled LAG member interfaces
   - Revert LACP mode from static LAG back to LACP active
   - Remove OS upgrade virtual network assignment
   - Assign server LAG interfaces to business virtual network
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
   - Routing zone (security zone)
   - Virtual networks and their corresponding connectivity templates for both OS upgrade and business virtual networks

## Usage

### Basic Usage

Pre-upgrade:
```bash
python apstra_server_vlan.py --server-name "server001" --routing-zone "blue" --os-vn "blue_vn_300"
```

Post-upgrade:
```bash
python apstra_server_vlan.py --server-name "server001" --routing-zone "blue" --os-vn "blue_vn_300" --business-vn "blue_vn_400" --post-upgrade
```

### Command Line Options

```bash
Required Arguments:
  --server-name, -s       Server name/label to upgrade
  --routing-zone, -rz     Routing zone name containing virtual networks
  --os-vn, -os            OS upgrade virtual network name (required for both phases)

Additional required arguments for Post-Upgrade:
  --business-vn, -bvn     Business virtual network name (required for post-upgrade)

Optional Arguments:
  --blueprint-name, -bp   Blueprint name (can also be in config file)
  --config, -c            Apstra configuration file (default: apstra_config.json)
  --post-upgrade          Run only post-upgrade phase (after OS upgrade is complete)
  --auto-complete         Automatically run both pre and post upgrade phases
  --dry-run               Dry run mode - discover configuration but make no changes
  --yes, -y               Automatically answer yes to all prompts (non-interactive mode)
```

### Workflow Examples

#### 1. Standard Two-Phase Approach (Recommended)

**Step 1: Pre-Upgrade**
```bash
python apstra_server_vlan.py -s "server001" -rz "blue" -os "blue_vn_300"
```

**Step 2: Perform OS Upgrade** (not handled by the script)

**Step 3: Post-Upgrade**
```bash
python apstra_server_vlan.py -s "server001" -rz "blue" -os "blue_vn_300" -bvn "blue_vn_400" --post-upgrade
```

#### 2. Dry Run (Discovery Only)
```bash
python apstra_server_vlan.py -s "server001" -rz "blue" --dry-run
```

#### 3. Auto-Complete (Testing Only)
```bash
python apstra_server_vlan.py -s "server001" -rz "blue" -os "blue_vn_300" -bvn "blue_vn_400" --auto-complete
```

## Script Features

### User Interaction & Safety
- **Interactive Interface Selection**: User chooses which LAG member interfaces to disable during pre-upgrade
- **User Consent Prompts**: Confirmation required before each major configuration change
- **Same VN Validation**: Prevents using identical virtual networks for OS and business phases
- **Dry-run Mode**: Test configuration discovery without making changes
- **Non-interactive Mode**: `--yes` flag for automation scenarios

### Enhanced Output & Monitoring
- **LAG Link Details**: Shows specific interface topology (server_interface ↔ switch:switch_interface)
- **Application Endpoint Info**: Displays interface details during VN assignments
- **Real-time Status**: Step-by-step progress with clear success/failure indicators
- **Comprehensive Logging**: Detailed logs with API calls, responses, and timing

### Automatic Discovery
- Server configuration and LAG connections
- Interface IDs and names for LAG members  
- Virtual network policies and application points
- Blueprint topology and routing zones
- Connectivity templates and policy hierarchy

### Error Handling & Validation
- **Argument Validation**: Ensures all required parameters are provided
- **VN Existence Check**: Validates virtual networks exist in specified routing zone
- **Policy Discovery**: Automatically finds connectivity templates for virtual networks
- **Graceful Error Recovery**: Clear error messages with suggested resolutions

## Logging

The script creates detailed logs in `apstra_server_vlan.log` including:
- All API calls and responses
- Configuration changes
- Error details
- Timing information

## Example Usage


```bash
# Dry run to verify configuration
python apstra_server_vlan.py -s "server001" -rz "blue" --dry-run

# Pre-upgrade phase
python apstra_server_vlan.py -s "server001" -rz "blue" -os "blue_vn_300"

# [Perform OS upgrade manually]

# Post-upgrade phase
python apstra_server_vlan.py -s "server001" -rz "blue" -os "blue_vn_300" -bvn "blue_vn_400" --post-upgrade
```

## Important Validation Rules

### Virtual Network Requirements
- **OS-VN and Business-VN Must Be Different**: The script validates that OS and business virtual networks are not the same
- **RZ and both VNs Must Exist**: Virtual networks must exist in the specified routing zone before running the script
- **Connectivity Templates Required**: Each virtual network must have corresponding connectivity templates configured

### Interactive Prompts
During execution, the script will prompt for:
1. **Interface Selection**: Choose which LAG member interfaces to disable (for redundancy)
2. **User Consent**: Confirmation before each major configuration change
3. **Same VN Warning**: If OS and business VNs are identical, the script will exit with an error


## Troubleshooting

### Common Issues

1. **Authentication Failed**
   - Verify credentials in config file
   - Check server URL and port

2. **Server Not Found**
   - Verify server name/label matches exactly
   - Check blueprint name is correct
   - Ensure server exists in the specified blueprint

3. **Virtual Network Not Found**
   - Verify VN names exist in the specified routing zone  
   - Check routing zone name is correct
   - Ensure VNs have connectivity templates configured

4. **Same Virtual Network Error**
   - Use different virtual networks for `--os-vn` and `--business-vn`
   - OS VN is for maintenance, Business VN is for production traffic

5. **No LAG Connections Found**
   - Verify server has dual-link LAG configuration
   - Check server is connected to leaf pair
   - Ensure cabling map data is available

6. **Policy Discovery Failed**
   - Check connectivity templates are properly configured
   - Verify virtual networks have associated policies
   - Ensure policy hierarchy is correct (batch → pipeline → AttachSingleVLAN)

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
