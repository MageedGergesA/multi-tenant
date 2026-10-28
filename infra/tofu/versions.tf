# ctl-1 and the platform's private network on Hetzner Cloud (ADR-009; DOC-05
# §6.6: "rebuild ctl-1 from IaC"). Host configuration is infra/ansible.
terraform {
  required_version = ">= 1.13.0"
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "= 1.69.0"
    }
  }

  # The state names every server and network; encrypted at rest (OpenTofu
  # state encryption) with a passphrase kept in the SOPS repo, given as
  # TF_VAR_state_passphrase. A plan file is encrypted the same way.
  encryption {
    key_provider "pbkdf2" "main" {
      passphrase = var.state_passphrase
    }
    method "aes_gcm" "main" {
      keys = key_provider.pbkdf2.main
    }
    state {
      method   = method.aes_gcm.main
      enforced = true
    }
    plan {
      method   = method.aes_gcm.main
      enforced = true
    }
  }
}

# The token comes from HCLOUD_TOKEN in the operator's shell, never a file here.
provider "hcloud" {}
