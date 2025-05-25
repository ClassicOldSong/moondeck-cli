#!/usr/bin/env python3
import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from random import randint
from pathlib import Path
from typing import Dict, Any, Optional, List
import uuid


# Add MoonDeck plugin directories to path
def get_plugin_dir():
    # If script is run from outside the plugin directory,
    # you'll need to specify the plugin path
    plugin_path = os.environ.get("MOONDECK_PATH")
    if plugin_path:
        return Path(plugin_path).resolve()
    # Otherwise assume we're in the plugin directory
    return Path(__file__).parent.resolve() / "moondeck" / "defaults"


def add_plugin_to_path():
    import sys
    plugin_dir = get_plugin_dir()
    directories = [["./"], ["python"], ["python", "lib"], ["python", "externals"]]
    for dir in directories:
        sys.path.append(str(plugin_dir.joinpath(*dir)))


add_plugin_to_path()


# Import MoonDeck modules
import python.lib.hostinfo as hostinfo
import python.lib.constants as constants
from python.lib.settings import settings_manager, UserSettings
from python.lib.logger import logger, set_log_filename
from python.lib.buddyrequests import SteamUiMode
from python.lib.buddyclient import BuddyClient, HelloResult, PcStateChange
from python.lib.buddyrequests import StreamState, AppState
from python.lib.utils import wake_on_lan, TimedPooler
from python.lib.runnerresult import Result, RunnerError

def get_default_config_dir() -> Path:
	"""Get the base directory for the application, whether running as script or exe."""
	if getattr(sys, 'frozen', False):
		# Running as PyInstaller exe
		return Path(sys.executable).parent
	else:
		# Running as script
		return Path(__file__).parent

# Global config paths - will be updated if --config-file is used
DEFAULT_CONFIG_DIR = get_default_config_dir()
CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"
# HOST_CONFIG will be determined from config.json

# Ensure default config directory exists
DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
stdout_handler.setFormatter(formatter)
logger.addHandler(stdout_handler)

class MoonDeckCLI:
    def __init__(self, config_file_path: Path = CONFIG_FILE):
        self.config_file_path = config_file_path
        self.config_dir = self.config_file_path.parent
        self.config_data = self.load_config()
        self.client_id = self.config_data.get("client_id")
        self.hosts_file_path = self.config_dir / self.config_data.get("hosts_file", "hosts.json")
        self.hosts = self.load_hosts()
        self.default_host = self.config_data.get("default_host")

    def load_config(self) -> Dict[str, Any]:
        """Load config.json or create it if it doesn't exist."""
        if self.config_file_path.exists():
            try:
                with open(self.config_file_path, 'r') as f:
                    data = json.load(f)
            except json.JSONDecodeError:
                logger.error(f"Error parsing config file: {self.config_file_path}. Reinitializing.")
                data = {}
        else:
            logger.info(f"Config file not found at {self.config_file_path}. Creating a new one.")
            data = {}

        # Ensure essential keys exist
        if "client_id" not in data or not data["client_id"]:
            data["client_id"] = str(uuid.uuid4())
            logger.info(f"Generated new client_id: {data['client_id']}")
        if "hosts_file" not in data:
            data["hosts_file"] = "hosts.json" # Default hosts file name
        if "default_host" not in data: # Ensure default_host key exists, can be None
            data["default_host"] = None

        self.save_config(data) # Save any changes (new file or new keys)
        return data

    def save_config(self, data: Optional[Dict[str, Any]] = None):
        """Save data to config.json"""
        if data is None:
            data = self.config_data

        # Ensure hosts_file is relative if config_dir is its parent
        hosts_file_path_obj = Path(data.get("hosts_file", "hosts.json"))
        if hosts_file_path_obj.is_absolute():
            try:
                relative_hosts_path = hosts_file_path_obj.relative_to(self.config_dir)
                data["hosts_file"] = str(relative_hosts_path)
            except ValueError:
                # If it's not relative to config_dir, keep absolute or store as is.
                # For simplicity, we'll assume it should be relative or just the filename.
                data["hosts_file"] = hosts_file_path_obj.name
        else:
            data["hosts_file"] = str(hosts_file_path_obj)


        with open(self.config_file_path, 'w') as f:
            json.dump(data, f, indent=2)
        self.config_data = data # Update internal state

    def load_hosts(self) -> Dict[str, Dict[str, Any]]:
        """Load saved hosts from the path specified in config.json"""
        self.hosts_file_path.parent.mkdir(parents=True, exist_ok=True) # Ensure directory for hosts.json exists
        if self.hosts_file_path.exists():
            try:
                with open(self.hosts_file_path, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logger.error(f"Error parsing hosts config file: {self.hosts_file_path}")
        return {}

    def save_hosts(self):
        """Save hosts to the path specified in config.json"""
        self.hosts_file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.hosts_file_path, 'w') as f:
            json.dump(self.hosts, f, indent=2)

    def load_default_host(self) -> Optional[str]:
        """Load default host from config data"""
        return self.config_data.get("default_host")

    def save_default_host(self, host_id: Optional[str]):
        """Save default host to config.json"""
        if host_id is not None:
            resolved_host = self._resolve_host_info(host_id)
            if resolved_host:
                host_id = resolved_host["id"]
            else:
                logger.error(f"Cannot set default host: Host '{host_id}' not found in hosts list")
                return False

        self.config_data["default_host"] = host_id
        self.save_config()
        self.default_host = host_id
        return True

    def _resolve_host_info(self, host_identifier: Optional[str]) -> Optional[Dict[str, Any]]:
        """
        Resolves host information from a given identifier (ID, IP, or hostname).

        Returns a dictionary with 'id', 'uniqueId', 'name', 'address',
        'buddy_port', 'client_id', 'mac' if found, otherwise None.
        The 'id' in the returned dict is the key from self.hosts.
        """
        if not host_identifier:
            return None

        # Case 1: host_identifier is a known host ID (key in self.hosts)
        if host_identifier in self.hosts:
            host_data = self.hosts[host_identifier]
            return {
                "id": host_identifier, # The ID used for lookup
                "uniqueId": host_data.get("uniqueId"),
                "name": host_data.get("hostName", host_identifier), # Fallback name to identifier
                "address": host_data.get("address"),
                "buddy_port": host_data.get("buddy_port"),
                "client_id": host_data.get("client_id"),
                "mac": host_data.get("mac")
            }

        # Case 2: host_identifier might be an IP address or hostname of a known host
        for hid, host_data in self.hosts.items():
            # Check if address or hostName matches the identifier
            # Ensure host_data.get("address") and host_data.get("hostName") are not None before comparison
            current_address = host_data.get("address")
            current_hostName = host_data.get("hostName")

            match_found = False
            if current_address and current_address == host_identifier:
                match_found = True
            elif current_hostName and current_hostName == host_identifier:
                match_found = True

            if match_found:
                return {
                    "id": hid, # The ID of the matched host entry
                    "uniqueId": host_data.get("uniqueId"),
                    "name": host_data.get("hostName", hid), # Fallback name to host's ID
                    "address": host_data.get("address"),
                    "buddy_port": host_data.get("buddy_port"),
                    "client_id": host_data.get("client_id"),
                    "mac": host_data.get("mac")
                }

        # Case 3: host_identifier not found in self.hosts by ID, address, or hostname
        return None

    async def scan_hosts_and_update(self, timeout: float = 5.0) -> List[Dict[str, Any]]:
        """Scan for available hosts, update internal hosts list, and save."""
        logger.info("Starting host scan and update process...")
        scanned_hosts_list = await hostinfo.scan_for_hosts(timeout=timeout)

        if scanned_hosts_list is None:
            logger.warning("Host scan returned no data or failed. No changes made to stored hosts.")
            return list(self.hosts.values())

        new_hosts_config = {} # This will become the new self.hosts

        # For easier lookup
        scanned_hosts_by_uid = {h['uniqueId']: h for h in scanned_hosts_list if 'uniqueId' in h}
        # Use a list of addresses for hosts found in scan, in case multiple UIDs map to same address (unlikely but safe)
        scanned_addresses_to_uid_map = {}
        for h in scanned_hosts_list:
            if 'uniqueId' in h and 'address' in h:
                if h['address'] not in scanned_addresses_to_uid_map:
                    scanned_addresses_to_uid_map[h['address']] = []
                scanned_addresses_to_uid_map[h['address']].append(h['uniqueId'])


        # Phase 1: Process existing hosts (self.hosts) against scan results
        for old_id, old_data in self.hosts.items():
            is_paired = bool(old_data.get("client_id"))
            old_address = old_data.get("address")

            # Case 1.1: Existing host (old_id) is found in scan by its ID (uniqueId)
            if old_id in scanned_hosts_by_uid:
                scanned_data = scanned_hosts_by_uid[old_id]
                updated_entry = old_data.copy()
                updated_entry["id"] = old_id # Ensure 'id' field matches key
                updated_entry["hostName"] = scanned_data.get("hostName", old_data.get("hostName"))
                updated_entry["address"] = scanned_data.get("address", old_data.get("address"))
                # Pairing info already in updated_entry via old_data.copy()
                new_hosts_config[old_id] = updated_entry
                logger.info(f"Host '{old_id}' found in scan by ID. Updated network info. Pairing status preserved.")

            # Case 1.2: Existing PAIRED host's address is found in scan, but its old_id is different from scanned uniqueId (ID correction)
            elif is_paired and old_address and old_address in scanned_addresses_to_uid_map:
                # Potentially multiple UIDs if address is shared, pick first or handle as error. Assume one primary UID per address from scan.
                correct_uid_for_address = scanned_addresses_to_uid_map[old_address][0] # Taking the first UID for this address

                if old_id != correct_uid_for_address:
                    logger.info(f"Paired host at address '{old_address}' (previously ID '{old_id}') now identified as '{correct_uid_for_address}'. Migrating.")
                    scanned_data_for_correct_uid = scanned_hosts_by_uid[correct_uid_for_address]

                    # If the correct_uid already has an entry (e.g. processed from another old_id or direct scan), merge carefully.
                    if correct_uid_for_address in new_hosts_config:
                        # This implies correct_uid was ALSO an old_id, or multiple old_ids map to this new correct_uid.
                        # Prioritize existing data for correct_uid if it's also paired, otherwise merge from old_id.
                        if not new_hosts_config[correct_uid_for_address].get("client_id"): # If target isn't paired, copy pairing.
                            logger.info(f"  Merging pairing from '{old_id}' into existing entry for '{correct_uid_for_address}'.")
                            new_hosts_config[correct_uid_for_address].update({k: v for k, v in old_data.items() if k == "client_id" or k == "buddy_port" or k=="mac"})
                    else: # Create new entry for correct_uid with migrated data
                        migrated_entry = old_data.copy()
                        migrated_entry["id"] = correct_uid_for_address
                        migrated_entry["hostName"] = scanned_data_for_correct_uid.get("hostName", old_data.get("hostName"))
                        migrated_entry["address"] = scanned_data_for_correct_uid.get("address") # Use fresh address
                        new_hosts_config[correct_uid_for_address] = migrated_entry
                    # The old_id entry is now superseded.
                else: # old_id == correct_uid_for_address, but wasn't caught by 'old_id in scanned_hosts_by_uid'
                      # This means the host was found by address, and its ID matches the scan.
                      # This case should ideally be covered by 1.1. If it reaches here, treat as found.
                    if old_id not in new_hosts_config: # If not already added
                        scanned_data = scanned_hosts_by_uid[old_id]
                        updated_entry = old_data.copy()
                        updated_entry["id"] = old_id
                        updated_entry["hostName"] = scanned_data.get("hostName", old_data.get("hostName"))
                        updated_entry["address"] = scanned_data.get("address", old_data.get("address"))
                        new_hosts_config[old_id] = updated_entry
                        logger.info(f"Paired host '{old_id}' (re-confirmed by address match) updated.")


            # Case 1.3: Existing PAIRED host is NOT found in scan (neither by ID nor by address for correction)
            elif is_paired: # and not found by ID (implicit from above) and address not in scan (implicit)
                if old_id not in new_hosts_config: # Ensure it wasn't added via some complex correction path
                    new_hosts_config[old_id] = old_data # Keep it as is (offline)
                    logger.info(f"Paired host '{old_id}' not found in current scan. Preserving (may be offline).")

            # Case 1.4: Existing UNPAIRED host is NOT found in scan (or its ID was corrected away)
            else: # Not paired and not processed above
                if old_id not in new_hosts_config: # if it wasn't ID-corrected and its data moved
                    logger.info(f"Unpaired host '{old_id}' not found in scan. Removing.")
                # Else (it was ID-corrected), its data moved, so the old_id is effectively removed.

        # Phase 2: Add newly discovered hosts that weren't related to any existing host
        for uid, scanned_data in scanned_hosts_by_uid.items():
            if uid not in new_hosts_config: # If it wasn't an existing host or a correction target
                new_entry = {
                    "id": uid,
                    "hostName": scanned_data.get("hostName"),
                    "address": scanned_data.get("address"),
                    # Potentially add default buddy_port if known, e.g. constants.DEFAULT_BUDDY_PORT
                }
                new_hosts_config[uid] = new_entry
                logger.info(f"New host '{uid}' (Name: {new_entry['hostName']}, IP: {new_entry['address']}) added from scan.")

        self.hosts = new_hosts_config
        self.save_hosts()
        logger.info("Hosts file updated based on scan results.")
        return list(self.hosts.values()) # Return list of dicts

    async def find_host(self, host_id: str, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
        """Find a specific host by ID"""
        return await hostinfo.find_host(host_id, timeout=timeout)

    async def get_buddy_info(self, address: str, buddy_port: int, client_id: str, timeout: float = 5.0):
        """Get information from Buddy server"""
        try:
            async with BuddyClient(address, buddy_port, client_id, timeout) as client:
                info_or_status = await client.get_host_info()
                if not isinstance(info_or_status, dict):
                    return {"status": info_or_status.name, "info": None}
                return {"status": "Online", "info": info_or_status}
        except Exception:
            logger.exception("Unhandled exception")
            return {"status": HelloResult.Exception.name, "info": None}

    async def start_pairing(self, address: str, buddy_port: int, client_id: str, pin: int, timeout: float = 5.0):
        """Start pairing with a host"""
        try:
            async with BuddyClient(address, buddy_port, client_id, timeout) as client:
                status = await client.start_pairing(pin)
                if status:
                    return status.name
                return "PairingStarted"
        except Exception:
            logger.exception("Unhandled exception")
            return HelloResult.Exception.name

    async def launch_game(self, client, app_id: str, big_picture_mode: bool = True,
                         ready_timeout: int = 30,
                         wait_for_quit: bool = False):
        """Launch a game on the host"""

        logger.info(f"Sending request to launch Steam if needed")
        result = await client.launch_steam(big_picture_mode=big_picture_mode)
        if result:
            logger.error(f"Failed to launch Steam: {result}")
            return False

        logger.info("Waiting for Steam to be ready")
        pooler = TimedPooler(retries=ready_timeout,
                            error_on_retry_out=Result.SteamDidNotReadyUpInTime)

        async for req in pooler(client.get_steam_ui_mode):
            mode = req["mode"]
            if mode != SteamUiMode.Unknown:
                break

        logger.info(f"Launching app {app_id}")
        result = await client.launch_app(app_id)
        if result:
            logger.error(f"Failed to launch app: {result}")
            return False

        if wait_for_quit:
            has_run = False
            logger.info(f"Waiting for game {app_id} to start...")
            while True:
                await asyncio.sleep(1)
                app_data_response = await client.get_streamed_app_data()

                if not isinstance(app_data_response, dict) or "data" not in app_data_response:
                    logger.error(f"Failed to get streamed app data or invalid format: {app_data_response}")
                    break

                current_app_data = app_data_response["data"]
                current_app_id = current_app_data.get("app_id")
                current_app_state = current_app_data.get("app_state")

                if current_app_id == app_id and current_app_state == AppState.Running:
                    if not has_run:
                        has_run = True
                        logger.info(f"Game {app_id} is running, waiting for it to quit...")
                    continue
                elif has_run and (current_app_id != app_id or current_app_state == AppState.Stopped):
                    logger.info(f"Game {app_id} has quit.")
                    break
                elif not has_run and (current_app_id != app_id or current_app_state == AppState.Stopped):
                    continue
                else:
                    logger.debug(f"Unhandled app data state: {current_app_data}")
                    await asyncio.sleep(1)

            if has_run:
                logger.info(f"Attempting to end stream for {app_id}.")
                end_stream_result = await client.end_stream()
                if end_stream_result:
                    logger.error(f"Failed to end stream after game quit: {end_stream_result}")
                else:
                    logger.info("Stream ended successfully after game quit.")

        return True

    async def get_current_app_data(self, address: str, buddy_port: int, client_id: str, timeout: float = 5.0):
        """Get current app data from host"""
        try:
            async with BuddyClient(address, buddy_port, client_id, timeout) as client:
                app_data_or_status = await client.get_streamed_app_data()
                if app_data_or_status and not isinstance(app_data_or_status, dict):
                    logger.error(f"While retrieving current app data: {app_data_or_status}")
                    return None
                return app_data_or_status
        except Exception:
            logger.exception("Unhandled exception")
            return None

    async def wake_host(self, address: str, mac: str):
        """Wake a host using Wake-on-LAN"""
        try:
            wake_on_lan(address, mac)
            return True
        except Exception:
            logger.exception("Unhandled exception")
            return False

    async def add_host(self, host_info: Dict[str, Any], make_default: bool = False):
        """Add or update a host in the config. The key for self.hosts will be host_info.get('id')."""
        # Ensure the 'id' field within the host_info dict matches the intended key.
        host_id_key = host_info.get("id")
        if not host_id_key:
            logger.error("Host info submitted to add_host is missing an 'id' field for keying.")
            # Attempt to use 'uniqueId' if 'id' is missing, for robustness, though 'id' should be set by caller.
            host_id_key = host_info.get("uniqueId")
            if not host_id_key:
                logger.error("Host info also missing 'uniqueId'. Cannot save host.")
                return False
            host_info["id"] = host_id_key # Set 'id' field from 'uniqueId' if that's what we are using as key

        logger.info(f"Adding/updating host with ID: {host_id_key}. Data: {host_info}")
        self.hosts[host_id_key] = host_info
        self.save_hosts()

        if make_default:
            self.save_default_host(host_id_key)
            # self.default_host = host_id_key # save_default_host already updates this

        return True

    async def get_gamestream_app_names(self, address: str, buddy_port: int, client_id: str, timeout: float = 5.0):
        """Get list of available GameStream apps from host"""
        try:
            async with BuddyClient(address, buddy_port, client_id, timeout) as client:
                names_or_status = await client.get_gamestream_app_names()
                if names_or_status and not isinstance(names_or_status, list):
                    logger.error(f"While retrieving gamestream app names: {names_or_status}")
                    return None
                return names_or_status
        except Exception:
            logger.exception("Unhandled exception")
            return None

    async def get_non_steam_app_data(self, address: str, buddy_port: int, client_id: str, timeout: float = 5.0, user_id: str = None):
        """Get list of non-Steam games from host"""
        try:
            async with BuddyClient(address, buddy_port, client_id, timeout) as client:
                apps_or_status = await client.get_non_steam_app_data(user_id=user_id)
                if apps_or_status and not isinstance(apps_or_status, list):
                    logger.error(f"While retrieving non-Steam app data: {apps_or_status}")
                    return None
                return apps_or_status
        except Exception:
            logger.exception("Unhandled exception")
            return None


    async def end_stream(self, address: str, buddy_port: int, client_id: str, timeout: float = 5.0):
        """End the current game stream on the host"""
        try:
            async with BuddyClient(address, buddy_port, client_id, timeout) as client:
                result = await client.end_stream()
                if result:
                    logger.error(f"Failed to end stream: {result}")
                    return False
                return True
        except Exception:
            logger.exception("Unhandled exception")
            return False


# Helper function to resolve host details for commands
def _get_validated_host_details(cli: MoonDeckCLI, cmd_args: argparse.Namespace, required_fields: List[str] = ["address", "client_id"]) -> Optional[Dict[str, Any]]:
    """
    Resolves host information based on command arguments or default host,
    determines effective connection parameters (address, port, client ID),
    and validates required fields.
    Returns a dictionary with host details or None if resolution/validation fails.
    """
    host_identifier_from_args = getattr(cmd_args, 'host', None)
    host_identifier = host_identifier_from_args or cli.default_host

    if not host_identifier:
        print("Error: No host specified and no default host set.")
        logger.warning("Attempted operation without host_identifier (neither --host nor default_host set).")
        return None

    resolved_host_data = cli._resolve_host_info(host_identifier)
    if not resolved_host_data:
        if host_identifier_from_args:
            print(f"Error: Host '{host_identifier_from_args}' not found in saved hosts or by IP/hostname.")
            logger.warning(f"Host resolution failed for explicit host: {host_identifier_from_args}")
        elif cli.default_host:
            print(f"Error: Default host '{cli.default_host}' not found or invalid.")
            logger.warning(f"Host resolution failed for default host: {cli.default_host}")
        else:
            print(f"Error: Host identifier '{host_identifier}' could not be resolved.")
            logger.warning(f"Host resolution failed for identifier: {host_identifier}")
        return None

    details = {"host_info": resolved_host_data}

    details["address"] = resolved_host_data.get("address")

    # Buddy Port Resolution
    # Priority: 1. Command's --port arg (if present, includes its argparse default)
    #           2. Host's stored buddy_port
    #           3. Global default (59999)
    command_specific_port = getattr(cmd_args, 'port', None)
    host_stored_port = resolved_host_data.get("buddy_port")

    if command_specific_port is not None:
        details["buddy_port"] = command_specific_port
    elif host_stored_port is not None:
        details["buddy_port"] = host_stored_port
    else:
        details["buddy_port"] = 59999 # Fallback default (e.g., constants.DEFAULT_BUDDY_PORT)

    # Client ID Resolution
    # Priority: 1. Command's --client-id arg (after main() populates it from cli.client_id if initially empty)
    #           2. Host's stored client_id
    #           3. Global cli.client_id (as a final fallback if others are None)
    cmd_client_id_val = getattr(cmd_args, 'client_id', None)
    host_client_id_val = resolved_host_data.get("client_id")
    details["client_id"] = cmd_client_id_val or host_client_id_val or cli.client_id

    details["host_display_name"] = resolved_host_data.get('name', resolved_host_data.get('id', 'Unknown Host'))

    # Validation of required fields based on the 'details' dict primarily,
    # and 'resolved_host_data' for fields like 'mac'.
    missing_field_names = []
    for field_key in required_fields:
        if field_key == "mac":
            if not resolved_host_data.get("mac"):
                missing_field_names.append("MAC address")
        elif not details.get(field_key): # Check if the key exists and is truthy in our constructed 'details'
             missing_field_names.append(field_key)

    if missing_field_names:
        missing_fields_str = ", ".join(missing_field_names)
        error_host_id_display = resolved_host_data.get('id', host_identifier)
        print(f"Error: Missing critical host information ({missing_fields_str}) for host ID '{error_host_id_display}'.")
        logger.warning(f"Validation failed for host '{error_host_id_display}'. Missing: {missing_fields_str}")
        return None

    return details


async def main():
    # Set up logging
    # set_log_filename(constants.LOG_FILE, rotate=True)
    set_log_filename("./cli.log", rotate=True)

    # Create CLI parser
    # A bit of a pre-parser to catch --config-file early
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--config-file", type=Path, help="Path to the config.json file.")
    pre_args, remaining_argv = pre_parser.parse_known_args()

    global CONFIG_FILE, DEFAULT_CONFIG_DIR
    if pre_args.config_file:
        CONFIG_FILE = pre_args.config_file.resolve()
        # Ensure the directory for the custom config file exists
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"Using custom config file: {CONFIG_FILE}")
    else:
        # Use default, ensure DEFAULT_CONFIG_DIR exists
        DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"
        logger.info(f"Using default config file: {CONFIG_FILE}")


    parser = argparse.ArgumentParser(description="MoonDeck CLI for pairing and launching games", parents=[pre_parser])
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan for available hosts")
    scan_parser.add_argument("--timeout", type=float, default=5.0, help="Scan timeout in seconds")

    # Pair command
    pair_parser = subparsers.add_parser("pair", help="Pair with a host")
    pair_parser.add_argument("--host", type=str, help="Host ID or IP address")
    pair_parser.add_argument("--port", type=int, default=59999, help="Buddy port")
    pair_parser.add_argument("--pin", type=int, default=randint(1, 9999), help="Pairing PIN")
    pair_parser.add_argument("--client-id", type=str, help="Client ID")
    pair_parser.add_argument("--no-default", action="store_false", help="Make this host the default")

    # Launch command
    launch_parser = subparsers.add_parser("launch", help="Launch a game on a host")
    launch_parser.add_argument("--host", type=str, help="Host ID or IP address (default: use default host)")
    launch_parser.add_argument("--port", type=int, default=59999, help="Buddy port")
    launch_parser.add_argument("--app-id", type=str, required=True, help="App ID to launch")
    launch_parser.add_argument("--client-id", type=str, help="Client ID")
    launch_parser.add_argument("--no-big-picture", action="store_true", help="Don't use big picture mode")
    launch_parser.add_argument("--wait", action="store_true", help="Wait for the game to quit and then end the stream")

    # Current app command
    current_app_parser = subparsers.add_parser("app-status", help="Get current app data from a host")
    current_app_parser.add_argument("--host", type=str, help="Host ID or IP address (default: use default host)")
    current_app_parser.add_argument("--port", type=int, default=59999, help="Buddy port")
    current_app_parser.add_argument("--client-id", type=str, help="Client ID")

    # Wake command
    wake_parser = subparsers.add_parser("wake", help="Wake a host using Wake-on-LAN")
    wake_parser.add_argument("--host", type=str, help="Host ID or IP address (default: use default host)")

    # List apps command
    apps_parser = subparsers.add_parser("list-apps", help="List available GameStream apps on a host")
    apps_parser.add_argument("--host", type=str, help="Host ID or IP address (default: use default host)")
    apps_parser.add_argument("--port", type=int, default=59999, help="Buddy port")
    apps_parser.add_argument("--client-id", type=str, help="Client ID")

    # List non-steam games command
    non_steam_parser = subparsers.add_parser("list-non-steam", help="List non-Steam games on a host")
    non_steam_parser.add_argument("--host", type=str, help="Host ID or IP address (default: use default host)")
    non_steam_parser.add_argument("--port", type=int, default=59999, help="Buddy port")
    non_steam_parser.add_argument("--client-id", type=str, help="Client ID")
    non_steam_parser.add_argument("--user-id", type=str, required=True, help="User ID")

    # End stream command
    end_stream_parser = subparsers.add_parser("end-stream", help="End the current game stream on a host")
    end_stream_parser.add_argument("--host", type=str, help="Host ID or IP address (default: use default host)")
    end_stream_parser.add_argument("--port", type=int, default=59999, help="Buddy port")
    end_stream_parser.add_argument("--client-id", type=str, help="Client ID")

    # List hosts command
    hosts_parser = subparsers.add_parser("list-hosts", help="List saved hosts")

    # Set default host command
    default_parser = subparsers.add_parser("set-default", help="Set default host")
    default_parser.add_argument("host", type=str, help="Host ID to set as default")

    # Clear default host command
    clear_default_parser = subparsers.add_parser("clear-default", help="Clear default host")

    # Parse arguments
    args = parser.parse_args(remaining_argv)

    # Create CLI instance, now with potentially custom config file path
    cli = MoonDeckCLI(config_file_path=CONFIG_FILE)

    # Store active BuddyClient if --wait is used for SIGINT handling
    active_client_for_sigint = None

    # SIGINT handler
    def sigint_handler(signum, frame):
        logger.info("SIGINT received, attempting to end stream if active...")
        if active_client_for_sigint and hasattr(active_client_for_sigint, 'end_stream'):
            try:
                # We are in a signal handler, so we can't use async/await directly.
                # We need to run this in a new event loop or find a synchronous way if available.
                # For now, let's schedule it on the existing loop if possible, though this is tricky.
                # A better approach might be to set a flag and let the main loop handle it.
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(active_client_for_sigint.end_stream(), loop=loop)
                    logger.info("Scheduled end_stream due to SIGINT.")
                else:
                    logger.warning("Event loop not running, cannot schedule end_stream for SIGINT.")
            except Exception as e:
                logger.error(f"Error trying to end stream on SIGINT: {e}")
        sys.exit(1) # Exit after attempting to cleanup

    signal.signal(signal.SIGINT, sigint_handler)

    # Generate a client ID if not provided and ensure it's consistent with config
    effective_client_id = cli.client_id
    if hasattr(args, 'client_id') and args.client_id:
        effective_client_id = args.client_id # Command line overrides config if provided
    elif not effective_client_id: # Should be set by MoonDeckCLI.__init__
        logger.error("Client ID not found in config and not generated. This should not happen.")
        effective_client_id = str(uuid.uuid4()) # Fallback, though __init__ should handle this

    # Update args.client_id if it exists in args namespace and wasn't overridden by command line
    if hasattr(args, 'client_id') and not args.client_id:
        args.client_id = effective_client_id

    # Execute command
    if args.command == "scan":
        updated_host_list = await cli.scan_hosts_and_update(args.timeout)
        if updated_host_list:
            print("Current known hosts (after scan and update):")
            for host_data in updated_host_list:
                host_id = host_data.get('id', 'N/A')
                is_paired = bool(host_data.get("client_id"))
                paired_marker = " (Paired)" if is_paired else " (Not Paired)"
                default_marker = " (default)" if host_id == cli.default_host else ""

                print(f"  ID     : {host_id}{default_marker}")
                print(f"  Name   : {host_data.get('hostName', 'Unknown')}")
                print(f"  Address: {host_data.get('address', 'Unknown')}")
                print(f"  Status : {paired_marker.strip()}")
                if 'buddy_port' in host_data:
                    print(f"  Buddy Port: {host_data['buddy_port']}")
                if 'mac' in host_data:
                    print(f"  MAC    : {host_data['mac']}")
                print()
        else:
            print("No hosts found or configured after scan.")

    elif args.command == "pair":
        # Determine address_to_pair and host_id_candidate_for_saving
        address_to_pair = None
        host_id_candidate_for_saving = args.host # This will be the key if no uniqueId comes from host
        effective_port = args.port
        host_unique_id = None # This is the uniqueId from the *host machine* itself
        host_name = None
        host_key_id = args.host # This is the key used in hosts.json, could be uniqueId or user-defined

        resolved_host_info = cli._resolve_host_info(args.host)

        if resolved_host_info:
            address_to_pair = resolved_host_info.get("address")
            effective_port = resolved_host_info.get("buddy_port") or args.port
            host_unique_id = resolved_host_info.get("uniqueId")
            host_name = resolved_host_info.get("hostName") or "Unknown Host"
            host_key_id = resolved_host_info.get("id") # This is the ID from hosts.json
            logger.info(f"Attempting to pair with known host. Resolved ID: '{host_key_id}', Address: {address_to_pair}, Port: {effective_port}")
        else:
            # Assume args.host is an IP address or a new identifier not yet in hosts.json
            address_to_pair = args.host
            # host_unique_id remains None initially for new hosts
            host_name = "Unknown Host (New)" # Placeholder name
            host_key_id = args.host # Candidate ID for saving, might be replaced by uniqueId from host
            logger.info(f"Attempting to pair with host specified as '{args.host}'. Assuming it's an address or new ID. Port: {effective_port}")

        if not address_to_pair:
            print("Error: Host address for pairing could not be determined.")
            return

        # effective_client_id is already determined globally in main()
        # args.client_id is updated with effective_client_id if it was None
        client_id_for_pairing = args.client_id

        print(f"Starting pairing with {address_to_pair}:{effective_port} using PIN {args.pin:04d} for client '{client_id_for_pairing}'...")
        result = await cli.start_pairing(address_to_pair, effective_port, client_id_for_pairing, args.pin)

        if result == "PairingStarted":
            print("Pairing initiated successfully. Waiting for host to complete pairing...")
            paired_host_info_final = None
            for _ in range(30): # Wait up to 30 seconds
                await asyncio.sleep(1)
                buddy_status_response = await cli.get_buddy_info(address_to_pair, effective_port, client_id_for_pairing)
                logger.debug(f"Post-pairing get_buddy_info response: {buddy_status_response}")

                if buddy_status_response["status"] == "Online" and buddy_status_response["info"]:
                    host_details_from_buddy = buddy_status_response["info"]
                    mac_address = host_details_from_buddy.get("mac")

                    # Determine the ID to save the host under
                    # Priority: 1. Actual uniqueId from host, 2. Original host_key_id (if resolved), 3. address_to_pair (if new)
                    id_to_save_under = host_unique_id or host_key_id or address_to_pair

                    paired_host_info_final = {
                        "id": id_to_save_under,
                        "uniqueId": host_unique_id, # Store the actual uniqueId from host
                        "hostName": host_name,
                        "address": address_to_pair,
                        "buddy_port": effective_port,
                        "client_id": client_id_for_pairing,
                        "mac": mac_address
                    }

                    # If the original host_key_id (e.g., an IP address used for initial lookup)
                    # is different from the id_to_save_under (e.g., a newly discovered uniqueId),
                    # and that old key exists, the scan_hosts_and_update process would normally clean it up.
                    # For pairing, we just ensure we save with the best ID.
                    # If host_key_id was different and existed, add_host might overwrite if keys are same, or add new if different.
                    # This is generally fine. The key is that `id_to_save_under` is now the definitive one.

                    if await cli.add_host(paired_host_info_final, args.make_default):
                        print(f"\nSuccessfully paired and saved host: '{host_name}' (ID: {id_to_save_under})")
                        if args.make_default:
                            print(f"Set '{id_to_save_under}' as default host.")
                    else:
                        print(f"Paired successfully, but failed to save host information for ID '{id_to_save_under}'.")
                    break
                elif buddy_status_response["status"] == "Pairing":
                    print(".", end="", flush=True)
                    continue
                else:
                    print(f"\nPairing confirmation failed or host status not Online. Status: {buddy_status_response['status']}")
                    if buddy_status_response["info"]:
                        print(f"Details: {buddy_status_response['info']}")
                    paired_host_info_final = None
                    break
            else:
                print("\nTimed out waiting for pairing confirmation from host.")

            if not paired_host_info_final:
                 logger.error("Pairing process completed, but final host information could not be obtained or saved.")

        elif result == "AlreadyPaired":
            print("This client ID is already paired with the host.")
            logger.info(f"Client '{client_id_for_pairing}' already paired with {address_to_pair}. Attempting to refresh host info.")
            buddy_status_response = await cli.get_buddy_info(address_to_pair, effective_port, client_id_for_pairing)
            if buddy_status_response["status"] == "Online" and buddy_status_response["info"]:
                full_host_details = buddy_status_response["info"]
                mac_address = full_host_details.get("mac")
                actual_host_unique_id = full_host_details.get("uniqueId")
                actual_host_name = full_host_details.get("hostName") or host_name

                id_to_save_under = actual_host_unique_id or host_key_id

                refreshed_host_info = {
                    "id": id_to_save_under,
                    "uniqueId": actual_host_unique_id,
                    "hostName": actual_host_name,
                    "address": address_to_pair,
                    "buddy_port": effective_port,
                    "client_id": client_id_for_pairing,
                    "mac": mac_address
                }
                if await cli.add_host(refreshed_host_info, args.make_default):
                    print(f"Refreshed and saved host information for already paired host: '{actual_host_name}' (ID: {id_to_save_under})")
                    if args.make_default:
                        print(f"Set/confirmed '{id_to_save_under}' as default host.")
                else:
                    print(f"Failed to save refreshed information for already paired host ID '{id_to_save_under}'.")
            else:
                print(f"Could not retrieve info for already paired host. Status: {buddy_status_response['status']}")
        else:
            print(f"Pairing failed with status: {result}")

    elif args.command == "launch":
        # Determine which host to use
        host_details = _get_validated_host_details(cli, args)
        if not host_details:
            return

        address = host_details["address"]
        buddy_port = host_details["buddy_port"]
        client_id = host_details["client_id"]
        host_display_name = host_details["host_display_name"]
        # No need for an additional check for address/client_id, _get_validated_host_details handles it.

        print(f"Launching app {args.app_id} on {host_display_name} ({address}:{buddy_port})...")

        async with BuddyClient(address, buddy_port, client_id, 5.0) as client_instance:
            active_client_for_sigint = client_instance
            result = await cli.launch_game(
                client_instance,
                args.app_id,
                not args.no_big_picture,
                wait_for_quit=args.wait
            )
            active_client_for_sigint = None

        if result:
            if args.wait:
                print("Game launched and quit successfully")
            else:
                print("Game launched successfully")
        else:
            print("Failed to launch game")

    elif args.command == "app-status":
        # Determine which host to use
        host_details = _get_validated_host_details(cli, args)
        if not host_details:
            return

        address = host_details["address"]
        buddy_port = host_details["buddy_port"]
        client_id = host_details["client_id"]
        host_display_name = host_details["host_display_name"]

        print(f"Retrieving current app data from {host_display_name} ({address}:{buddy_port})...")
        app_status = await cli.get_current_app_data(address, buddy_port, client_id)

        if app_status:
            app_data = app_status.get('data')
            print(f"Current app: {app_data.get('app_id')}")
            print(f"App state: {"STARTED" if app_data.get('app_state') == AppState.Running else "STOPPED" if app_data.get('app_state') == AppState.Stopped else "UPDATING" if app_data.get('app_state') == AppState.Updating else "UNKNOWN"}")
        else:
            print("No current app data found")

    elif args.command == "wake":
        # Determine which host to use
        host_details = _get_validated_host_details(cli, args, required_fields=["address", "mac"])
        if not host_details:
            return

        address = host_details["address"]
        mac = host_details["host_info"].get("mac") # Already validated by helper
        host_display_name = host_details["host_display_name"]

        # The explicit check for address and mac is now handled by _get_validated_host_details
        # if not address or not mac:
        #     print(f"Error: Missing host address or MAC address for host ID '{host_details['host_info'].get('id')}'. Cannot send Wake-on-LAN.")
        #     return

        print(f"Waking host {host_display_name} (MAC: {mac}, Target IP: {address})...")
        result = await cli.wake_host(address, mac)
        if result:
            print("Wake-on-LAN packet sent successfully")
        else:
            print("Failed to send Wake-on-LAN packet")

    elif args.command == "list-apps":
        # Determine which host to use
        host_details = _get_validated_host_details(cli, args)
        if not host_details:
            return

        address = host_details["address"]
        buddy_port = host_details["buddy_port"]
        client_id = host_details["client_id"]
        host_display_name = host_details["host_display_name"]

        print(f"Retrieving available apps from {host_display_name} ({address}:{buddy_port})...")
        apps = await cli.get_gamestream_app_names(address, buddy_port, client_id)

        if apps:
            print("Available apps:")
            for i, app in enumerate(apps):
                print(f"  {i+1}. {app}")
        else:
            print("No apps found or failed to retrieve app list")

    elif args.command == "list-non-steam":
        # Determine which host to use
        host_details = _get_validated_host_details(cli, args) # Default required_fields are fine
        if not host_details:
            return

        address = host_details["address"]
        buddy_port = host_details["buddy_port"]
        client_id = host_details["client_id"]
        host_display_name = host_details["host_display_name"]
        user_id = args.user_id # This is specific to list-non-steam

        print(f"Retrieving non-Steam games from {host_display_name} ({address}:{buddy_port})...")
        apps = await cli.get_non_steam_app_data(address, buddy_port, client_id, user_id=user_id)

        if apps:
            print("Non-Steam games:")
            for i, app in enumerate(apps):
                print(f"  {i+1}. [{app.get('app_id')}] {app.get('app_name')}")
        else:
            print("No non-Steam games found or failed to retrieve game list")


    elif args.command == "list-hosts":
        if cli.hosts:
            print("Saved hosts:")
            print()
            for host_id, host_info in cli.hosts.items():
                default_marker = " (default)" if host_id == cli.default_host else ""
                print("===================")
                print()
                print(f"  ID: {host_id}{default_marker}")
                print(f"  Name: {host_info.get('hostName', 'Unknown')}")
                print(f"  Address: {host_info.get('address', 'Unknown')}")
                print(f"  Buddy Port: {host_info.get('buddy_port', 59999)}")
                print(f"  MAC: {host_info.get('mac', 'N/A')}")
                print()
        else:
            print("No hosts saved")

    elif args.command == "set-default":
        if cli.save_default_host(args.host):
            print(f"Set '{args.host}' as default host")
        else:
            print(f"Error: Host '{args.host}' not found in saved hosts")

    elif args.command == "clear-default":
        cli.save_default_host(None)
        print("Default host cleared")

    elif args.command == "end-stream":
        # Determine which host to use
        host_details = _get_validated_host_details(cli, args)
        if not host_details:
            return

        address = host_details["address"]
        buddy_port = host_details["buddy_port"]
        client_id = host_details["client_id"]
        host_display_name = host_details["host_display_name"]

        print(f"Ending stream on {host_display_name} ({address}:{buddy_port})...")
        result = await cli.end_stream(address, buddy_port, client_id)
        if result:
            print("Stream ended successfully")
        else:
            print("Failed to end stream")

    else:
        parser.print_help()

if __name__ == "__main__":
    asyncio.run(main())
