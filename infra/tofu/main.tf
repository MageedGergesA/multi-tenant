resource "hcloud_network" "platform" {
  name              = "platform"
  ip_range          = var.network_cidr
  delete_protection = true # every host is on it
  labels            = { platform = "odoo-cloud" }
}

resource "hcloud_network_subnet" "hosts" {
  network_id   = hcloud_network.platform.id
  type         = "cloud"
  network_zone = var.network_zone
  ip_range     = var.hosts_subnet
}

resource "hcloud_ssh_key" "operator" {
  for_each   = var.ssh_public_keys
  name       = "operator-${each.key}"
  public_key = each.value
}

# Inbound: WireGuard from anywhere (it authenticates every packet), ICMP, and
# SSH only from admin_cidrs while bootstrapping. The host's nftables
# (infra/ansible, role base) is the second layer.
resource "hcloud_firewall" "ctl" {
  name   = "ctl-1"
  labels = { platform = "odoo-cloud", role = "ctl" }

  rule {
    direction  = "in"
    protocol   = "udp"
    port       = tostring(var.wireguard_port)
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  dynamic "rule" {
    for_each = length(var.admin_cidrs) > 0 ? [1] : []
    content {
      direction  = "in"
      protocol   = "tcp"
      port       = "22"
      source_ips = var.admin_cidrs
    }
  }
}

resource "hcloud_server" "ctl" {
  name               = "ctl-1"
  server_type        = var.server_type
  image              = var.image
  location           = var.location
  ssh_keys           = [for k in hcloud_ssh_key.operator : k.id]
  firewall_ids       = [hcloud_firewall.ctl.id]
  delete_protection  = true
  rebuild_protection = true
  backups            = false # bucket C holds what ctl-1 needs (DOC-05 §1)
  labels             = { platform = "odoo-cloud", role = "ctl" }

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  network {
    network_id = hcloud_network.platform.id
    ip         = var.ctl_private_ip
  }

  depends_on = [hcloud_network_subnet.hosts]

  lifecycle {
    prevent_destroy = true
    # A new image release mustn't replace the running control plane.
    ignore_changes = [image, ssh_keys]
  }
}
