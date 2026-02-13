from typing import Optional
import requests
import logging
import os
import json
import argparse
import time
from datetime import datetime
from packaging.version import Version, InvalidVersion
import yaml
from pathlib import Path
import tarfile
import xml.etree.ElementTree as ET

SPLUNK_USER = os.getenv('SPLUNK_USER')
SPLUNK_PASS = os.getenv('SPLUNK_PASS')
SPLUNK_API_TOKEN = os.getenv('SPLUNK_API_TOKEN')
STACK = os.getenv('SPLUNK_STACK')
SPLUNKBASE_API_URL = 'https://splunkbase.splunk.com/api/v1/app'
SPLUNK_API_URL = f'https://admin.splunk.com/{STACK}/adminconfig/v2'
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_ARTIFACTS_DIR = 'artifacts'


def get_splunkbase_login_token() -> str:
    """
    Get Splunkbase authentication token using Splunk user credentials.
    
    Authenticates against the Splunkbase account login API and extracts
    the session token from the XML response.
    
    :return: Splunkbase authentication token
    :raises Exception: If authentication fails or token cannot be parsed
    """
    logger.info('Receiving Splunkbase authentication token')
    r = requests.post(
        'https://splunkbase.splunk.com/api/account:login/',
        data={
            'username': SPLUNK_USER,
            'password': SPLUNK_PASS
        }
    )
    if r.status_code != 200:
        logger.error(f'Error while receiving Splunkbase token: {r.text}')
        raise Exception('Failed to get Splunkbase authentication token')
    
    # Parse XML response to extract token from <id> element
    root = ET.fromstring(r.text)
    # Handle XML namespace
    ns = {'atom': 'http://www.w3.org/2005/Atom'}
    token_element = root.find('atom:id', ns)
    
    if token_element is None:
        logger.error('Token not found in Splunkbase response')
        raise Exception('Failed to parse Splunkbase authentication token')
    
    logger.info('Successfully received Splunkbase authentication token')
    return token_element.text

def get_current_stack_info(splunkbase_apps: list[dict] | None = None) -> tuple[dict, Optional[str]]:
    """
    Get the current Splunk Cloud stack configuration including the Splunk version
    and CIM (Common Information Model) version.
    
    Uses the ACS (Admin Config Service) API to retrieve the stack status, then
    extracts version information for compatibility checking.
    
    :param splunkbase_apps: Optional list of installed apps to extract CIM version from
    :return: Tuple of (current_cim_version, current_splunk_version)
    """

    # Get current stack version
    r = requests.get(f'{SPLUNK_API_URL}/status', headers={
        'Authorization': f'Bearer {SPLUNK_API_TOKEN}',
    })
    if r.status_code != 200:
        logger.error(f'Error checking pre updates: {r.text}')
    stack_info = r.json()

    # Extract stack version from nested structure
    current_stack_version = stack_info.get('infrastructure', {}).get('stackVersion', '')
    logger.info(f'Current Splunk stack version: {current_stack_version}')
    
    # Convert "9.3.2411.121" to "9.3" to match product_versions format
    if current_stack_version:
        version_parts = parse_version(current_stack_version)
        current_splunk_version = f"{version_parts.major}.{version_parts.minor}"
    else:
        current_splunk_version = None
    
    logger.info(f'Current Splunk version: {current_splunk_version}')

    if splunkbase_apps:
        for app in splunkbase_apps:
            if app.get('appID') == 'Splunk_SA_CIM' and app.get('status') == 'installed':
                current_cim_version = parse_version(app.get('version'))
                current_cim_version = f"{current_cim_version.major}.x"
                logger.info(f'Current CIM version: {current_cim_version}')
                break
    else:
        logger.warning('No Splunkbase apps found')
        current_cim_version = None

    return current_cim_version, current_splunk_version

def enrich_apps_releases_with_stack_compatibility(splunkbase_apps: list[dict]) -> list[dict]:
    """
    Enrich available releases/updates of apps with compatibility information
    against the current Splunk Cloud stack (CIM version and Splunk version).
    
    For each app that has updates available, this checks every release version
    and marks whether it is compatible with the current CIM and Splunk versions.
    
    :param splunkbase_apps: List of app dictionaries with available_versions populated
    :return: The same list with compatibility flags added to each release
    """
    current_cim_version, current_splunk_version = get_current_stack_info(splunkbase_apps)
    for app in splunkbase_apps:
        if app.get('update_available') is True:
            for release in app.get('available_versions'):
                # Check CIM version compatibility
                if current_cim_version in release.get('CIM_versions', []):
                    release['current_cim_version_compatible'] = True
                    logger.debug(f"App release {release.get('filename')} CIM version is compatible")
                else:
                    release['current_cim_version_compatible'] = False
                    logger.debug(f"App release {release.get('filename')} CIM version is not compatible")
                # Check Splunk version compatibility
                if current_splunk_version in release.get('product_versions', []):
                    release['current_splunk_version_compatible'] = True
                    logger.debug(f"App release {release.get('filename')} Splunk version is compatible")
                else:
                    release['current_splunk_version_compatible'] = False
                    logger.debug(f"App release {release.get('filename')} Splunk version is not compatible")
                    
    return splunkbase_apps

def get_app_license_url(splunkbase_id: str) -> str:
    """
    Get the license URL for a Splunkbase app.
    
    Required by the ACS API when installing/upgrading apps to acknowledge
    the app's license terms.
    
    :param splunkbase_id: The Splunkbase app ID
    :return: License URL string, or default ISC license if not found
    """
    default_license_url = 'http://opensource.org/licenses/ISC'
    
    logger.debug(f'Fetching license URL for Splunkbase app ID: {splunkbase_id}')
    
    try:
        r = requests.get(f'{SPLUNKBASE_API_URL}/{splunkbase_id}')
        
        if r.status_code != 200:
            logger.warning(f'Error fetching license URL for app {splunkbase_id}: {r.text}')
            return default_license_url
        
        app_info = r.json()
        license_url = app_info.get('license_url')
        
        if license_url:
            logger.debug(f'Found license URL for app {splunkbase_id}: {license_url}')
            return license_url
        else:
            logger.warning(f'No license_url found for app {splunkbase_id}, using default')
            return default_license_url
            
    except Exception as e:
        logger.warning(f'Exception fetching license URL for app {splunkbase_id}: {e}')
        return default_license_url


def get_app_releases(splunkbase_id: str) -> list[dict]:
    """
    Get available release versions for a Splunkbase app from the Splunkbase API.

    :param splunkbase_id: The Splunkbase app ID
    :return: List of release dictionaries containing version info, compatibility data, etc.
    """
    logger.debug(f'Fetching releases for Splunkbase app ID: {splunkbase_id}')

    r = requests.get(f'{SPLUNKBASE_API_URL}/{splunkbase_id}/release')

    if r.status_code != 200:
        logger.warning(f'Error fetching releases for app {splunkbase_id}: {r.text}')
        return []

    releases = r.json()
    versions = releases
    logger.debug(f'Found {len(versions)} releases for app {splunkbase_id}')

    return versions

def parse_version(version_str: str) -> Version | None:
    """
    Parse a version string into a Version object.
    
    :param version_str: Version string (e.g., "9.3.1")
    :return: Version object or None if parsing fails
    """
    try:
        return Version(version_str)
    except InvalidVersion:
        return None

def load_config(config_file: str = None) -> dict:
    """
    Load configuration from YAML file.
    
    :param config_file: Path to config file. If None, uses default location (config.yml in script directory)
    :return: Configuration dictionary
    """
    if config_file is None:
        # Default to config.yml in the same directory as this script
        script_dir = Path(__file__).parent
        config_file = script_dir / 'config.yml'
    else:
        config_file = Path(config_file)
    
    if not config_file.exists():
        logger.debug(f'Config file not found: {config_file}')
        exit(1)
        return {}
    
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f) or {}
        logger.info(f'Loaded configuration from {config_file}')
        return config
    except yaml.YAMLError as e:
        logger.error(f'Error parsing config file {config_file}: {e}')
        return {}
    except Exception as e:
        logger.error(f'Error loading config file {config_file}: {e}')
        return {}

def get_excluded_splunkbase_ids(config: dict) -> set[str]:
    """
    Extract excluded Splunkbase IDs from config.
    
    Apps in the exclusion list will be skipped during the upgrade process.
    
    :param config: Configuration dictionary
    :return: Set of excluded Splunkbase IDs as strings
    """
    excluded_ids = set()
    
    excluded_apps = config.get('excluded_apps', [])
    if not excluded_apps:
        return excluded_ids
    
    for app_entry in excluded_apps:
        if isinstance(app_entry, dict):
            splunkbase_id = app_entry.get('splunkbase_id')
            if splunkbase_id:
                excluded_ids.add(str(splunkbase_id))
                reason = app_entry.get('reason', 'No reason provided')
                logger.debug(f'Excluded app ID {splunkbase_id}: {reason}')
    
    if excluded_ids:
        logger.info(f'Found {len(excluded_ids)} excluded app(s): {", ".join(sorted(excluded_ids))}')
    
    return excluded_ids

def enrich_apps_with_releases(apps: list[dict]) -> list[dict]:
    """
    Enrich the Splunkbase apps list with available release versions from the
    Splunkbase API. For each app, fetches all releases and filters to only
    versions newer than the currently installed version.

    :param apps: List of Splunkbase app dictionaries
    :return: Enriched list with 'available_versions' and 'update_available' fields added
    """
    logger.info(f'Enriching {len(apps)} apps with release information')

    for app in apps:
        splunkbase_id = app.get('splunkbaseID')
        app_current_version = app.get('version')
        app['update_available'] = False

        if splunkbase_id:
            all_releases = get_app_releases(splunkbase_id)
            current_ver = parse_version(app_current_version) if app_current_version else None

            # Filter to only include versions newer than current
            newer_versions = []
            if current_ver and all_releases:
                for release in all_releases:
                    release_ver = parse_version(release.get('name'))
                    if release_ver and release_ver > current_ver:
                        newer_versions.append(release)
                        app['update_available'] = True

            app['available_versions'] = newer_versions

        else:
            logger.warning(f"App {app.get('appID')} has no splunkbaseID")
            app['available_versions'] = []

    # Enrich apps with stack compatibility information
    apps = enrich_apps_releases_with_stack_compatibility(apps)
    return apps

def list_splunkbase_apps() -> list[dict]:
    """
    List all Splunkbase apps installed on Splunk Cloud via the ACS API.
    
    :return: List of Splunkbase app dictionaries
    """
    logger.info(f'Fetching Splunkbase apps from Splunk Cloud stack: {STACK}')
    r = requests.get(
        f'{SPLUNK_API_URL}/apps/victoria',
        params={
            "splunkbase": "true",
            "count": 0,
        },
        headers={
            'Authorization': f'Bearer {SPLUNK_API_TOKEN}',
        }
    )
    
    if r.status_code != 200:
        logger.error(f'Error fetching installed apps: {r.text}')
        return []

    splunkbase_apps = r.json().get('apps', [])
    logger.info(f'Found {len(splunkbase_apps)} Splunkbase apps')
    
    return splunkbase_apps

def validate_exported_file(file_path: str) -> tuple[bool, Optional[str]]:
    """
    Validate that the exported file is a valid tar.gz archive and not an error response.
    
    The ACS export API may return error messages as plain text instead of a valid
    archive, so this validates the downloaded file before proceeding.
    
    :param file_path: Path to the exported file
    :return: Tuple of (is_valid, error_message)
    """
    try:
        with tarfile.open(file_path, 'r:gz') as tar:
            tar.getmembers()
        return True, None
    except (tarfile.TarError, tarfile.ReadError):
        # Not a valid tar.gz, try to read error message
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            return False, content
        except Exception as e:
            return False, f"Cannot read file: {e}"

def export_splunkbase_app_files(current_app_version: str, app_id: str, output_dir: str = DEFAULT_ARTIFACTS_DIR) -> bool:
    """
    Export (backup) the currently installed Splunkbase app package via the ACS API.
    
    Downloads the app's tar.gz package before upgrading, serving as a backup
    in case a rollback is needed.

    :param current_app_version: The currently installed version string
    :param app_id: The app ID to export
    :param output_dir: Directory to save the exported file
    :return: True if export was successful, False otherwise
    """
    os.makedirs(output_dir, exist_ok=True)

    current_app_version = current_app_version.replace('.', '')
    if not app_id:
        logger.warning(f"App has no appID, skipping: {app_id}")
        return False

    filename = f"{app_id}_{current_app_version}.tar.gz"
    file_path = os.path.join(output_dir, filename)
    max_attempts = 2
    
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            logger.info(f'Retrying export for {app_id} (attempt {attempt}/{max_attempts})')
        else:
            logger.info(f'Exporting app package for: {app_id}')

        r = requests.get(
            f'{SPLUNK_API_URL}/apps/victoria/export/download/{app_id}',
            headers={
                'Authorization': f'Bearer {SPLUNK_API_TOKEN}',
            },
            stream=True
        )

        if r.status_code != 200:
            logger.error(f'Error exporting app {app_id}: {r.status_code} - {r.text}')
            if attempt == max_attempts:
                return False
            continue

        with open(file_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

        logger.info(f'Successfully downloaded app {app_id} to {file_path}')
        
        # Validate the exported file
        is_valid, error_msg = validate_exported_file(file_path)
        
        if not is_valid:
            logger.error(f'Exported file validation failed for {app_id}: {error_msg}')
            try:
                os.remove(file_path)
                logger.debug(f'Removed invalid file: {file_path}')
            except Exception as e:
                logger.warning(f'Failed to remove invalid file {file_path}: {e}')
            
            if attempt == max_attempts:
                return False
            continue
        
        logger.info(f'Successfully exported and validated app {app_id}')
        return True
    
    return False

def export_apps_to_json(apps: list[dict], output_dir: str = DEFAULT_ARTIFACTS_DIR) -> str:
    """
    Export the apps list (with enriched update/compatibility data) to a JSON file.
    
    :param apps: List of app dictionaries to export
    :param output_dir: Directory to save the JSON file
    :return: Path to the exported JSON file
    """
    os.makedirs(output_dir, exist_ok=True)

    filename = "splunkbase_apps.json"
    file_path = os.path.join(output_dir, filename)

    with open(file_path, 'w') as f:
        json.dump({
            'stack': STACK,
            'total_apps': len(apps),
            'apps': apps
        }, f, indent=2)

    logger.info(f'Exported Splunkbase apps to {file_path}')
    return file_path

def load_apps_from_json(json_file: str) -> list[dict]:
    """
    Load apps from a previously exported JSON file.
    
    :param json_file: Path to the JSON file
    :return: List of app dictionaries
    """
    logger.info(f'Loading apps from {json_file}')
    
    if not os.path.exists(json_file):
        logger.error(f'JSON file not found: {json_file}')
        exit(1)
    
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    apps = data.get('apps', [])
    logger.info(f'Loaded {len(apps)} apps from JSON file')
    return apps

def check_app_compatibility(app: dict, force_bypass: bool = False) -> tuple[bool, str]:
    """
    Check if any release version of the app is compatible with the current stack.
    
    Compatibility is determined by:
    - CIM version compatibility
    - Splunk version compatibility
    - Cloud compatibility flag
    - No restart required (stateChangeRequiresRestart must be False)
    
    :param app: App dictionary with available_versions populated
    :param force_bypass: If True, skip compatibility checks and return the first available version
    :return: Tuple of (is_compatible, compatible_version_string)
    """
    if not app.get('update_available'):
        return False, None

    stateChangeRequiresRestart = app.get('stateChangeRequiresRestart', True)
    for release in app.get('available_versions', []):
        cim_compatible = release.get('current_cim_version_compatible', False)
        splunk_compatible = release.get('current_splunk_version_compatible', False)
        cloud_compatible = release.get('cloud_compatible', False)
        
        if force_bypass:
            return True, release.get('name')

        if cim_compatible and splunk_compatible and cloud_compatible and not stateChangeRequiresRestart:
            return True, release.get('name')
    
    return False, None

def upgrade_splunkbase_apps(apps: list[dict], splunkbase_token: str, force: bool = False, excluded_ids: set[str] = None):
    """
    Upgrade Splunkbase apps that have compatible updates available.
    
    For each app with an available update:
    1. Skip if the app is in the exclusion list
    2. Check compatibility with the current stack
    3. Export (backup) the currently installed version
    4. Perform the upgrade via the ACS API
    5. Poll for installation status until complete or timeout
    
    :param apps: List of apps to upgrade
    :param splunkbase_token: Splunkbase authentication token
    :param force: If True, bypass compatibility checks
    :param excluded_ids: Set of excluded Splunkbase IDs to skip
    """
    if excluded_ids is None:
        excluded_ids = set()

    apps_to_upgrade = [app for app in apps if app.get('update_available') is True]
    logger.info(f'Found {len(apps_to_upgrade)} apps with updates to check for upgrade')
    
    if force:
        logger.warning('Force mode enabled - bypassing compatibility checks')

    for app in apps_to_upgrade:
        splunkbase_id = app.get('splunkbaseID')
        app_label = app.get('label', 'Unknown')
        
        try:
            # Skip app upgrade if app is in exclusion list
            if splunkbase_id and str(splunkbase_id) in excluded_ids:
                logger.info(f"Skipping app upgrade for {app_label} (splunkbaseID: {splunkbase_id}) - in exclusion list")
                continue

            is_compatible, compatible_version = check_app_compatibility(app, force_bypass=force)
            
            if is_compatible:
                app_id = app.get('appID')
                splunkbase_id = app.get('splunkbaseID')
                get_current_app_version = requests.get(
                    f'{SPLUNK_API_URL}/apps/victoria/{app_id}',
                    params={
                        "splunkbase": "true",
                        "count": 0,
                    },
                    headers={
                        'Authorization': f'Bearer {SPLUNK_API_TOKEN}',
                    }
                )
            
                if get_current_app_version.status_code != 200:
                    logger.error(f'Error fetching current app version for {app_label}: {get_current_app_version.text}')
                    continue

                current_app_version = get_current_app_version.json().get('version', '')
                exported_app = export_splunkbase_app_files(current_app_version, app_id)
                if not exported_app:
                    logger.error(f"Failed to export app {app_label}. Skipping upgrade.")
                    continue
                
                logger.info(f"Upgrading app {app_label} from {current_app_version} to {compatible_version}")
                
                # Fetch the app's license URL
                license_url = get_app_license_url(splunkbase_id)

                # Poll for installation status until "installed" or timeout (5 minutes)
                timeout_seconds = 300  # 5 minutes
                poll_interval = 5  # seconds between polls
                start_time = time.time()
                status = None
                
                while True:
                    elapsed_time = time.time() - start_time
                    
                    # Check timeout
                    if elapsed_time >= timeout_seconds:
                        logger.error(f"Timeout waiting for app {app_label} installation. Status still '{status}' after {timeout_seconds} seconds.")
                        break
                    
                    r = requests.patch(
                        f'{SPLUNK_API_URL}/apps/victoria/{app_id}',
                        params={
                            "splunkbase": "true",
                            "splunkbaseID": splunkbase_id
                        },
                        data={
                            'version': compatible_version
                        },
                        headers={
                            'X-Splunkbase-Authorization': splunkbase_token,
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'ACS-Licensing-Ack': license_url,
                            'Authorization': f'Bearer {SPLUNK_API_TOKEN}',
                        }
                    )
                    
                    if r.status_code not in (200, 202):
                        logger.error(f"Error installing app {app_label}: {r.status_code} - {r.text}")
                        break
                    
                    response_data = r.json()
                    status = response_data.get('status', '')
                    
                    if status == 'installed':
                        logger.info(f"Successfully upgraded app {app_label} from {current_app_version} to {compatible_version}")
                        break
                    elif status == 'processing':
                        logger.info(f"App {app_label} installation in progress (status: {status}). Waiting {poll_interval}s... ({int(elapsed_time)}s/{timeout_seconds}s)")
                        time.sleep(poll_interval)
                    else:
                        logger.error(f"App {app_label} returned unexpected status: {status}")
                        break
            else:
                logger.warning(f"App {app_label} has no compatible version for the current stack")

        except Exception as e:
            logger.error(f"Error upgrading app {app_label}: {e}")

def enrich_app_versions(apps: list[dict], force: bool = False) -> list[dict]:
    """
    Update app version fields to reflect the target upgrade version.
    
    For apps that have a compatible update, this updates the 'version' field
    to the target version. Used when exporting the JSON so it reflects
    the intended state after upgrade.
    
    :param apps: List of app dictionaries
    :param force: If True, bypass compatibility checks
    :return: Updated list of apps
    """
    apps_to_upgrade = [app for app in apps if app.get('update_available') is True]
    for app in apps_to_upgrade:
        is_compatible, compatible_version = check_app_compatibility(app, force_bypass=force)
            
        if is_compatible:
            logger.info(f"App ({app.get('label')}) will be upgraded from {app.get('version')} to {compatible_version}") 
            app['version'] = compatible_version

    return apps

def check_updates(output_dir: str = DEFAULT_ARTIFACTS_DIR, force: bool = False):
    """
    Check for available app updates and export results to JSON.
    
    This is the main "check" workflow:
    1. Fetches all installed Splunkbase apps from the stack
    2. Queries the Splunkbase API for newer versions of each app
    3. Checks compatibility of each new version against the current stack
    4. Exports the enriched data to a JSON file
    
    :param output_dir: Directory to export the JSON file
    :param force: If True, include all newer versions regardless of compatibility
    :return: List of enriched app dictionaries
    """
    logger.info('Checking for app updates...')
    
    # List Splunkbase apps and enrich them with available release versions
    splunkbase_apps = enrich_apps_with_releases(list_splunkbase_apps())

    splunkbase_apps = enrich_app_versions(splunkbase_apps, force=force)
    
    # Export apps metadata to JSON
    json_file = export_apps_to_json(splunkbase_apps, output_dir)
    
    logger.info(f'Update check completed. Results exported to: {json_file}')
    return splunkbase_apps

def upgrade_apps_from_json(json_file: str, force: bool = False, excluded_ids: set[str] = None):
    """
    Upgrade apps using a previously exported JSON file as input.
    
    This is the main "upgrade" workflow:
    1. Loads the app list from the JSON file
    2. Authenticates with Splunkbase to get a download token
    3. Upgrades each app that has update_available=true
    
    :param json_file: Path to the splunkbase_apps.json file
    :param force: If True, bypass compatibility checks
    :param excluded_ids: Set of excluded Splunkbase IDs to skip from upgrade
    """
    logger.info('Starting app upgrade process...')
    
    # Load apps from JSON file
    apps = load_apps_from_json(json_file)
    
    # Get splunkbase token
    splunkbase_token = get_splunkbase_login_token()
    
    # Upgrade apps
    upgrade_splunkbase_apps(apps, splunkbase_token, force=force, excluded_ids=excluded_ids)
    
    logger.info('App upgrade process completed')

def main():
    parser = argparse.ArgumentParser(
        description='Manage Splunkbase apps on Splunk Cloud - check for updates and upgrade apps via the ACS API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check for updates and export to JSON
  python splunkbase_apps.py --check-updates

  # Upgrade apps from JSON file
  python splunkbase_apps.py --upgrade-apps splunkbase_apps.json

  # Upgrade apps with force mode (bypass compatibility checks)
  python splunkbase_apps.py --upgrade-apps splunkbase_apps.json --force
        """
    )
    
    # Create mutually exclusive group for main actions
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        '--check-updates',
        action='store_true',
        help='Check for app updates and export results to JSON'
    )
    action_group.add_argument(
        '--upgrade-apps',
        metavar='JSON_FILE',
        type=str,
        help='Upgrade apps from the specified JSON file (e.g., splunkbase_apps.json)'
    )
    
    # Optional arguments
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force upgrade bypassing compatibility checks and upgrade to the latest version'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default=DEFAULT_ARTIFACTS_DIR,
        help=f'Output directory for JSON export (default: {DEFAULT_ARTIFACTS_DIR})'
    )
    parser.add_argument(
        '--config-file',
        type=str,
        default=None,
        help='Path to config file for exclusion list and other settings (default: config.yml)'
    )
    
    args = parser.parse_args()
    
    # Check for required environment variables
    if not SPLUNK_API_TOKEN:
        logger.error('SPLUNK_API_TOKEN environment variable is required')
        exit(1)
    
    if not STACK:
        logger.error('SPLUNK_STACK environment variable is required')
        exit(1)
    
    # Load config file
    config = load_config(args.config_file)
    excluded_ids = get_excluded_splunkbase_ids(config)
    
    # Execute based on the selected action
    if args.check_updates:
        check_updates(output_dir=args.output_dir, force=args.force)
    
    elif args.upgrade_apps:
        if args.force:
            logger.warning('--force flag enabled: Compatibility checks will be bypassed!')
        upgrade_apps_from_json(args.upgrade_apps, force=args.force, excluded_ids=excluded_ids)

if __name__ == '__main__':
    main()
