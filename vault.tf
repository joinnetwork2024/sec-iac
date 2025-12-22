# Define the Vault provider
provider "vault" {
  # 1. Address: Fetches the VAULT_ADDR from the environment (e.g., http://192.168.1.125:30222)
  # This makes the provider configuration cleaner.
  address = var.vault_addr

  # 2. Authentication: Uses the AppRole login method
  auth_login {
    # Path where AppRole is enabled in Vault
    path = "auth/approle/login"

    # Parameters needed for AppRole login
    parameters = {
      # Role ID is generally considered less sensitive and can be in the code
      role_id = var.vaultroleid

      # Secret ID is highly sensitive and MUST be sourced from an environment variable
      secret_id = var.vaultsecretid
      sensitive = true
    }
  }
}