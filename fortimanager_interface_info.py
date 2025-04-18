#!/usr/bin/env python3

import urllib3
import requests
import json
import sys
import argparse
from typing import Dict, List, Any, Optional
import pandas as pd
from datetime import datetime
from pathlib import Path

# Import FortiManager class or use it directly if installed via pip
try:
    from pyFortiManagerAPI import FortiManager
except ImportError:
    print("pyfortimanagerapi module not found. Please install it or ensure it's in the same directory.")
    sys.exit(1)

def list_devices(fmg: FortiManager, adom_name: str) -> List[Dict[str, Any]]:
    """
    List all devices in the specified ADOM
    
    Args:
        fmg: FortiManager instance
        adom_name: ADOM name
    
    Returns:
        List of devices
    """
    session = fmg.login()
    
    payload = {
        "method": "get",
        "params": [
            {
                "url": f"/dvmdb/adom/{adom_name}/device",
                "fields": ["name", "ip", "sn", "os_ver", "platform_str", "conn_status"]
            }
        ],
        "session": fmg.sessionid
    }
    
    response = session.post(url=fmg.base_url, json=payload, verify=fmg.verify)
    
    if response.status_code != 200:
        raise Exception(f"Failed to get devices: {response.text}")
    
    result = response.json()
    
    if result.get("result", [{}])[0].get("status", {}).get("code", 0) != 0:
        error_msg = result.get("result", [{}])[0].get("status", {}).get("message", "Unknown error")
        raise Exception(f"API error when retrieving devices: {error_msg}")
    
    return result.get("result", [{}])[0].get("data", [])

def list_adoms(fmg: FortiManager) -> List[Dict[str, Any]]:
    """
    List all ADOMs in FortiManager
    
    Args:
        fmg: FortiManager instance
    
    Returns:
        List of ADOMs
    """
    adoms_result = fmg.get_adoms()
    
    if not adoms_result or adoms_result[0].get("status", {}).get("code", 0) != 0:
        error_msg = adoms_result[0].get("status", {}).get("message", "Unknown error") if adoms_result else "No data returned"
        raise Exception(f"API error when retrieving ADOMs: {error_msg}")
    
    return adoms_result[0].get("data", [])

def select_device(devices: List[Dict[str, Any]]) -> Optional[str]:
    """
    Display a list of devices and let the user select one
    
    Args:
        devices: List of device information dictionaries
    
    Returns:
        Selected device name or None if canceled
    """
    if not devices:
        print("No devices found in this ADOM.")
        return None
    
    print("\n=== AVAILABLE DEVICES ===")
    for i, device in enumerate(devices, 1):
        device_name = device.get('name', 'N/A')
        device_ip = device.get('ip', 'N/A')
        device_model = device.get('platform_str', 'N/A')
        device_os = device.get('os_ver', 'N/A')
        device_status = device.get('conn_status', 0)
        status_text = "Connected" if device_status == 1 else "Disconnected"
        
        print(f"{i}. {device_name} - {device_ip} ({device_model}, FortiOS {device_os}, {status_text})")
    
    print("0. Cancel")
    
    while True:
        try:
            choice = int(input("\nSelect a device (enter number): "))
            if choice == 0:
                return None
            if 1 <= choice <= len(devices):
                return devices[choice-1].get('name')
            print("Invalid selection. Please try again.")
        except ValueError:
            print("Please enter a number.")

def select_adom(adoms: List[Dict[str, Any]]) -> Optional[str]:
    """
    Display a list of ADOMs and let the user select one
    
    Args:
        adoms: List of ADOM information dictionaries
    
    Returns:
        Selected ADOM name or None if canceled
    """
    if not adoms:
        print("No ADOMs found.")
        return None
    
    print("\n=== AVAILABLE ADOMs ===")
    for i, adom in enumerate(adoms, 1):
        adom_name = adom.get('name', 'N/A')
        adom_version = adom.get('os_ver', 'N/A')
        print(f"{i}. {adom_name} (Version: {adom_version})")
    
    print("0. Cancel")
    
    while True:
        try:
            choice = int(input("\nSelect an ADOM (enter number): "))
            if choice == 0:
                return None
            if 1 <= choice <= len(adoms):
                return adoms[choice-1].get('name')
            print("Invalid selection. Please try again.")
        except ValueError:
            print("Please enter a number.")

def get_device_interface_info(
    fmg: FortiManager,
    device_name: str,
    adom_name: str = "root"
) -> Dict[str, Any]:
    """
    Retrieve interface, subinterface, and VLAN information for a specified device.
    
    Args:
        fmg: FortiManager instance
        device_name: Name of the device to query
        adom_name: ADOM name (default: root)
    
    Returns:
        Dictionary containing interface information
    """
    # Login to FortiManager
    session = fmg.login()
    
    # Get basic interfaces
    interfaces_payload = {
        "method": "get",
        "params": [
            {
                "url": f"/pm/config/device/{device_name}/vdom/root/interface"
            }
        ],
        "session": fmg.sessionid
    }
    
    interfaces_response = session.post(
        url=fmg.base_url, 
        json=interfaces_payload, 
        verify=fmg.verify
    )
    
    if interfaces_response.status_code != 200:
        raise Exception(f"Failed to get interfaces: {interfaces_response.text}")
    
    # Get VLAN interfaces
    vlan_payload = {
        "method": "get",
        "params": [
            {
                "url": f"/pm/config/device/{device_name}/vdom/root/system/interface",
                "filter": [["type", "==", "vlan"]]
            }
        ],
        "session": fmg.sessionid
    }
    
    vlan_response = session.post(
        url=fmg.base_url, 
        json=vlan_payload, 
        verify=fmg.verify
    )
    
    if vlan_response.status_code != 200:
        raise Exception(f"Failed to get VLAN interfaces: {vlan_response.text}")
    
    # Get subinterfaces (non-VLAN virtual interfaces)
    subinterface_payload = {
        "method": "get",
        "params": [
            {
                "url": f"/pm/config/device/{device_name}/vdom/root/system/interface",
                "filter": [["vdom", "==", "root"], ["type", "==", "vlanif"]]  # Changed to vlanif to distinguish from VLANs
            }
        ],
        "session": fmg.sessionid
    }
    
    subinterface_response = session.post(
        url=fmg.base_url, 
        json=subinterface_payload, 
        verify=fmg.verify
    )
    
    if subinterface_response.status_code != 200:
        raise Exception(f"Failed to get subinterfaces: {subinterface_response.text}")
    
    # Process and combine results
    interfaces_data = interfaces_response.json()
    vlan_data = vlan_response.json()
    subinterface_data = subinterface_response.json()
    
    # Check for API errors in responses
    for resp_name, resp in [("interfaces", interfaces_data), ("VLANs", vlan_data), ("subinterfaces", subinterface_data)]:
        if resp.get("result", [{}])[0].get("status", {}).get("code", 0) != 0:
            error_msg = resp.get("result", [{}])[0].get("status", {}).get("message", "Unknown error")
            print(f"API error when retrieving {resp_name}: {error_msg}")
    
    result = {
        "physical_interfaces": interfaces_data.get("result", [{}])[0].get("data", []),
        "vlan_interfaces": vlan_data.get("result", [{}])[0].get("data", []),
        "subinterfaces": subinterface_data.get("result", [{}])[0].get("data", [])
    }
    
    return result

def display_interface_summary(interface_info: Dict[str, Any]) -> None:
    """
    Display a summary of the device interfaces
    
    Args:
        interface_info: Dictionary containing interface information
    """
    print("\n=== PHYSICAL INTERFACES ===")
    if not interface_info["physical_interfaces"]:
        print("No physical interfaces found.")
    else:
        for interface in interface_info["physical_interfaces"]:
            print(f"Name: {interface.get('name', 'N/A')}")
            print(f"  Status: {'Up' if interface.get('status') == 'up' else 'Down'}")
            print(f"  IP: {interface.get('ip', 'N/A')}")
            print(f"  Type: {interface.get('type', 'N/A')}")
            print()
    
    print("\n=== VLAN INTERFACES ===")
    if not interface_info["vlan_interfaces"]:
        print("No VLAN interfaces found.")
    else:
        for vlan in interface_info["vlan_interfaces"]:
            print(f"Name: {vlan.get('name', 'N/A')}")
            print(f"  VLAN ID: {vlan.get('vlanid', 'N/A')}")
            print(f"  Interface: {vlan.get('interface', 'N/A')}")
            ip = vlan.get('ip', 'N/A')
            netmask = vlan.get('netmask', 'N/A')
            print(f"  IP: {ip}/{netmask}" if ip != 'N/A' else "  IP: Not configured")
            print()
    
    print("\n=== SUBINTERFACES ===")
    if not interface_info["subinterfaces"]:
        print("No subinterfaces found.")
    else:
        for subif in interface_info["subinterfaces"]:
            print(f"Name: {subif.get('name', 'N/A')}")
            print(f"  Parent: {subif.get('interface', 'N/A')}")
            print(f"  VLAN ID: {subif.get('vlanid', 'N/A')}")
            ip = subif.get('ip', 'N/A')
            netmask = subif.get('netmask', 'N/A')
            print(f"  IP: {ip}/{netmask}" if ip != 'N/A' else "  IP: Not configured")
            print()

def convert_to_dataframes(interface_info: Dict[str, Any]) -> Dict[str, pd.DataFrame]:
    """
    Convert interface information to pandas DataFrames
    
    Args:
        interface_info: Dictionary containing interface information
        
    Returns:
        Dictionary of DataFrames for each interface type
    """
    # Process physical interfaces
    physical_interfaces = []
    for iface in interface_info["physical_interfaces"]:
        physical_interfaces.append({
            "Name": iface.get("name", "N/A"),
            "Status": "Up" if iface.get("status") == "up" else "Down",
            "IP Address": iface.get("ip", "N/A"),
            "Type": iface.get("type", "N/A"),
            "Description": iface.get("description", "")
        })
    
    # Process VLAN interfaces
    vlan_interfaces = []
    for vlan in interface_info["vlan_interfaces"]:
        vlan_interfaces.append({
            "Name": vlan.get("name", "N/A"),
            "VLAN ID": vlan.get("vlanid", "N/A"),
            "Parent Interface": vlan.get("interface", "N/A"),
            "IP Address": vlan.get("ip", "N/A"),
            "Netmask": vlan.get("netmask", "N/A"),
            "Description": vlan.get("description", "")
        })
    
    # Process subinterfaces
    subinterfaces = []
    for subif in interface_info["subinterfaces"]:
        subinterfaces.append({
            "Name": subif.get("name", "N/A"),
            "Parent Interface": subif.get("interface", "N/A"),
            "VLAN ID": subif.get("vlanid", "N/A"),
            "IP Address": subif.get("ip", "N/A"),
            "Netmask": subif.get("netmask", "N/A"),
            "Description": subif.get("description", "")
        })
    
    return {
        "physical_interfaces": pd.DataFrame(physical_interfaces),
        "vlan_interfaces": pd.DataFrame(vlan_interfaces),
        "subinterfaces": pd.DataFrame(subinterfaces)
    }

def export_to_excel(interface_info: Dict[str, Any], device_name: str, output_file: Optional[str] = None) -> str:
    """
    Export interface information to Excel
    
    Args:
        interface_info: Dictionary containing interface information
        device_name: Name of the device
        output_file: Output file path (optional)
        
    Returns:
        Path to the created Excel file
    """
    # Convert data to DataFrames
    dfs = convert_to_dataframes(interface_info)
    
    # If no output file specified, create one with timestamp
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"{device_name}_interfaces_{timestamp}.xlsx"
    
    # Create Excel writer
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        # Write each DataFrame to a different sheet
        dfs["physical_interfaces"].to_excel(writer, sheet_name="Physical Interfaces", index=False)
        dfs["vlan_interfaces"].to_excel(writer, sheet_name="VLAN Interfaces", index=False)
        dfs["subinterfaces"].to_excel(writer, sheet_name="Subinterfaces", index=False)
    
    return output_file

def main():
    from dotenv import load_dotenv
    import os
    load_dotenv()

    # Set up argument parsing
    parser = argparse.ArgumentParser(description='Get interface information from FortiManager')
    parser.add_argument('--device', required=False, help='Device name to query')
    parser.add_argument('--adom', required=False, help='ADOM name (default: from env or ESN-INTERNAL-7K)')
    parser.add_argument('--excel', action='store_true', help='Export interface info to Excel file')
    parser.add_argument('--output', help='Output Excel file path (default: devicename_interfaces_timestamp.xlsx)')
    args = parser.parse_args()

    # Configuration parameters
    host = os.getenv("FORTIMANAGER_IP")
    username = os.getenv("FORTIMANAGER_USERNAME")
    password = os.getenv("FORTIMANAGER_PASSWORD")
    adom = args.adom or os.getenv("FORTIMANAGER_ADOM") or "ESN-INTERNAL-7K"
    
    # Validate credentials
    if not all([host, username, password]):
        print("Error: Missing FortiManager credentials. Check your environment variables.")
        sys.exit(1)
    
    print(f"Connecting to FortiManager at {host}...")
    
    # Create FortiManager instance
    fmg = FortiManager(
        host=host,
        username=username,
        password=password,
        adom=adom,
        verify=False  # Set to True in production environment
    )
    
    try:
        # Login to FortiManager
        fmg.login()
        print("Connected successfully to FortiManager.")
        
        # List and select ADOM if not specified in arguments
        if not args.adom:
            try:
                print("Retrieving available ADOMs...")
                adoms = list_adoms(fmg)
                selected_adom = select_adom(adoms)
                if selected_adom:
                    adom = selected_adom
                    fmg.set_adom(adom)
            except Exception as e:
                print(f"Warning: Failed to list ADOMs: {str(e)}")
                print(f"Using default ADOM: {adom}")
        
        print(f"Using ADOM: {adom}")
        
        # Get device name from arguments or list devices for selection
        device_name = args.device
        if not device_name:
            try:
                print("\nRetrieving devices from ADOM...")
                devices = list_devices(fmg, adom)
                device_name = select_device(devices)
                if not device_name:
                    print("No device selected. Exiting.")
                    sys.exit(0)
            except Exception as e:
                print(f"Error listing devices: {str(e)}")
                device_name = input("Enter device name manually to query: ")
                if not device_name:
                    print("Error: Device name is required")
                    sys.exit(1)
        
        print(f"\nQuerying interfaces for device '{device_name}' in ADOM '{adom}'...")
        
        # Get interface information
        interface_info = get_device_interface_info(fmg, device_name, adom)
        
        # Display interface summary
        display_interface_summary(interface_info)
        
        # Export to Excel if requested
        if args.excel:
            excel_file = export_to_excel(interface_info, device_name, args.output)
            print(f"\nInterface information exported to Excel file: {excel_file}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        print("Please check if the device name and ADOM are correct.")
    
    finally:
        # Always logout
        try:
            fmg.logout()
            print("\nSuccessfully logged out from FortiManager")
        except Exception as e:
            print(f"Warning: Failed to logout properly: {str(e)}")

if __name__ == "__main__":
    # Disable SSL warnings when verify=False
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()