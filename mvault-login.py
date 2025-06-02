import argparse
import getpass
import yaml
import sys
import os
import hvac
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def validate_vault_addr(addr: str) -> str:
    """Validate and normalize Vault address."""
    try:
        if not addr.startswith(('http://', 'https://')):
            addr = f'https://{addr}'
        parsed = urlparse(addr)
        if not parsed.netloc:
            raise ValueError("Invalid Vault address")
        return addr
    except Exception as e:
        logger.error(f"Invalid Vault address: {addr}")
        raise ValueError(f"Invalid Vault address: {e}")

def load_yaml_config(yaml_file: str) -> Dict[str, Any]:
    """Load and validate YAML configuration file."""
    try:
        if not os.path.exists(yaml_file):
            raise FileNotFoundError(f"YAML file not found: {yaml_file}")
        
        with open(yaml_file, 'r') as f:
            config = yaml.safe_load(f)
        
        if not isinstance(config, dict) or 'solutions' not in config:
            raise ValueError("Invalid YAML structure: missing 'solutions' key")
        
        return config
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML file: {e}")
        raise
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        raise

def get_login_details(config: Dict[str, Any], solution: str, environment: str) -> Dict[str, Any]:
    """Get login configuration for specified solution and environment."""
    try:
        login_config = config['solutions'][solution][environment]
        required_fields = ['vault_addr', 'login_method']
        missing_fields = [field for field in required_fields if field not in login_config]
        
        if missing_fields:
            raise KeyError(f"Missing required fields: {', '.join(missing_fields)}")
        
        # Validate Vault address
        login_config['vault_addr'] = validate_vault_addr(login_config['vault_addr'])
        return login_config
    
    except KeyError as e:
        logger.error(f"Configuration error: {e}")
        raise KeyError(f"Missing configuration for solution '{solution}', environment '{environment}'")

def perform_login(login_config: Dict[str, Any], username: Optional[str] = None, password: Optional[str] = None) -> Optional[str]:
    """Perform Vault login and return token."""
    vault_addr = login_config['vault_addr']
    login_method = login_config['login_method']
    
    # Initialize Vault client
    client = hvac.Client(url=vault_addr)
    
    try:
        if login_method == "userpass":
            return _handle_userpass_login(client, login_config, username, password)
        elif login_method == "oidc":
            return _handle_oidc_login(client, login_config)
        else:
            raise ValueError(f"Unsupported login method: {login_method}")
    
    except Exception as e:
        logger.error(f"Login failed: {e}")
        raise

def _handle_userpass_login(client: hvac.Client, config: Dict[str, Any], username: Optional[str], password: Optional[str]) -> str:
    """Handle userpass authentication method."""
    username = username or config.get("username") or os.environ.get("VAULT_USERNAME") or input("Username: ")
    password = password or os.environ.get("VAULT_PASSWORD") or getpass.getpass("Password: ")
    
    try:
        result = client.auth.userpass.login(
            username=username,
            password=password
        )
        logger.info(f"Successfully logged in as '{username}' using userpass")
        return result['auth']['client_token']
    except Exception as e:
        logger.error(f"Userpass authentication failed: {e}")
        raise

def _handle_oidc_login(client: hvac.Client, config: Dict[str, Any]) -> str:
    """Handle OIDC authentication method."""
    oidc_path = config.get("oidc_path", "oidc")
    try:
        result = client.auth.oidc.oidc_callback(
            path=oidc_path
        )
        logger.info("Successfully authenticated using OIDC")
        return result['auth']['client_token']
    except Exception as e:
        logger.error(f"OIDC authentication failed: {e}")
        raise

def main():
    parser = argparse.ArgumentParser(
        description="Vault login helper for multiple solutions/environments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  VAULT_USERNAME  - Username for userpass authentication
  VAULT_PASSWORD  - Password for userpass authentication
  VAULT_ADDR     - Override Vault address from config
  VAULT_SKIP_VERIFY - Skip TLS verification (not recommended)
        """
    )
    parser.add_argument("--yaml", required=True, help="Path to the YAML configuration file")
    parser.add_argument("--solution", required=True, help="Solution name (e.g., solution_a)")
    parser.add_argument("--env", required=True, help="Environment name (e.g., dev, prod)")
    parser.add_argument("--username", help="Username (only for userpass method)")
    parser.add_argument("--password", help="Password (only for userpass method)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--no-verify", action="store_true", help="Skip TLS verification (not recommended)")

    args = parser.parse_args()

    # Configure debug logging if requested
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        config = load_yaml_config(args.yaml)
        login_config = get_login_details(config, args.solution, args.env)
        
        # Override Vault address if specified in environment
        if os.environ.get("VAULT_ADDR"):
            login_config['vault_addr'] = validate_vault_addr(os.environ["VAULT_ADDR"])
        
        # Handle TLS verification
        if args.no_verify or os.environ.get("VAULT_SKIP_VERIFY"):
            import urllib3
            urllib3.disable_warnings()
            logger.warning("TLS verification is disabled!")
        
        token = perform_login(login_config, args.username, args.password)
        if token:
            # Print token in a format suitable for evaluation
            print(f"export VAULT_TOKEN={token}")
    
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
