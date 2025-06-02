# Vault Authentication Helper

A Python script to simplify HashiCorp Vault authentication across multiple solutions and environments. This tool supports different authentication methods and provides a consistent interface for logging into Vault instances.

## Features

- Multiple authentication methods support (userpass, OIDC)
- Configuration via YAML for multiple solutions and environments
- Environment variable support for sensitive data
- Secure credential handling
- Configurable TLS verification
- Debug logging capabilities
- Token export for shell integration

## Prerequisites

- Python 3.7+
- Access to HashiCorp Vault instance(s)
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/vault-auth-helper.git
cd vault-auth-helper
```

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Create a `config.yaml` file with your Vault configurations. Example:

```yaml
solutions:
  dev_solution:
    dev:
      vault_addr: "https://vault.dev.example.com"
      login_method: "userpass"
      username: "dev-user"
    prod:
      vault_addr: "https://vault.prod.example.com"
      login_method: "oidc"
      oidc_path: "oidc"
```

### Configuration Options

- `vault_addr`: Vault server address (with or without https://)
- `login_method`: Authentication method ("userpass" or "oidc")
- `username`: Optional username for userpass authentication
- `oidc_path`: Optional OIDC path (defaults to "oidc")

## Usage

### Basic Usage

```bash
python vault-auth.py --yaml config.yaml --solution dev_solution --env dev
```

### Command Line Options

- `--yaml`: Path to YAML configuration file (required)
- `--solution`: Solution name from config (required)
- `--env`: Environment name from config (required)
- `--username`: Override username for userpass authentication
- `--password`: Provide password (not recommended, use env vars instead)
- `--debug`: Enable debug logging
- `--no-verify`: Skip TLS verification (not recommended)

### Environment Variables

The script supports several environment variables:

- `VAULT_USERNAME`: Username for userpass authentication
- `VAULT_PASSWORD`: Password for userpass authentication
- `VAULT_ADDR`: Override Vault address from config
- `VAULT_SKIP_VERIFY`: Skip TLS verification if set

### Shell Integration

The script outputs the Vault token in a format suitable for shell evaluation:

```bash
# Bash/Zsh
eval $(python vault-auth.py --yaml config.yaml --solution dev_solution --env dev)

# Fish
python vault-auth.py --yaml config.yaml --solution dev_solution --env dev | source
```

## Security Considerations

1. Always use HTTPS for production Vault instances
2. Don't store passwords in the configuration file
3. Use environment variables for sensitive data
4. Avoid using `--no-verify` in production
5. Keep your configuration file secure

## Error Handling

The script provides detailed error messages and logging:

- Configuration errors (missing or invalid YAML)
- Connection errors (invalid Vault address)
- Authentication errors (invalid credentials)
- TLS verification errors

Enable debug logging with `--debug` for more detailed output.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Troubleshooting

### Common Issues

1. **Connection Errors**
   - Verify Vault address is correct
   - Check network connectivity
   - Verify TLS certificates if using HTTPS

2. **Authentication Failures**
   - Verify credentials
   - Check authentication method configuration
   - Ensure OIDC is properly configured

3. **Configuration Issues**
   - Validate YAML syntax
   - Check required fields
   - Verify environment names

### Debug Mode

Enable debug mode for detailed logging:

```bash
python vault-auth.py --yaml config.yaml --solution dev_solution --env dev --debug
```

## Support

For issues and feature requests, please create an issue in the repository. 