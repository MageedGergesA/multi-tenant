variable "state_passphrase" {
  description = "Encrypts the state and plans (at least 16 characters); from the SOPS repo."
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.state_passphrase) >= 16
    error_message = "The state passphrase must be at least 16 characters."
  }
}

variable "location" {
  description = "Hetzner location of ctl-1."
  type        = string
  default     = "fsn1"
}

variable "network_zone" {
  description = "Network zone of the location (fsn1, nbg1, hel1: eu-central)."
  type        = string
  default     = "eu-central"
}

variable "server_type" {
  description = "ctl-1's server type (DOC-06 sizes it; small: the API, its PostgreSQL, the workers)."
  type        = string
  default     = "cx22"
}

variable "image" {
  description = "Ubuntu 24.04 LTS, the platform's base (ADR-010)."
  type        = string
  default     = "ubuntu-24.04"
}

variable "network_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "hosts_subnet" {
  type    = string
  default = "10.0.0.0/24"
}

variable "ctl_private_ip" {
  description = "Fixed, so a rebuilt ctl-1 keeps it (DOC-07 RB-06/RB-10)."
  type        = string
  default     = "10.0.0.2"
}

variable "ssh_public_keys" {
  description = "Operators' SSH public keys, name => key; root's authorized_keys on first boot."
  type        = map(string)
  validation {
    condition     = length(var.ssh_public_keys) > 0
    error_message = "At least one operator SSH key is needed to bootstrap."
  }
}

variable "admin_cidrs" {
  description = "Where SSH is allowed from over the public network, for the first Ansible run only; empty afterwards: SSH is then only through WireGuard (ADR-H0-003)."
  type        = list(string)
  default     = []
}

variable "wireguard_port" {
  type    = number
  default = 51820
}

variable "db_server_type" {
  description = "db-1 (local NVMe for the tenants' databases; DOC-06 sizes it)."
  type        = string
  default     = "ccx23"
}

variable "db_private_ip" {
  type    = string
  default = "10.0.0.3"
}

variable "app_hosts" {
  description = "App hosts: name => {server_type, private_ip, volume_gb (the tenants' filestore)}."
  type = map(object({
    server_type = string
    private_ip  = string
    volume_gb   = number
  }))
  default = {
    "app-1" = { server_type = "cpx41", private_ip = "10.0.0.16", volume_gb = 200 }
  }
}
