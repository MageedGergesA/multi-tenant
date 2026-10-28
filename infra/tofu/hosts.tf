# db-1 and the app hosts (ADR-003). Configured by infra/ansible (db.yml, and the app play).

# db-1 is reached over the private network (PostgreSQL, from the app hosts; nftables on the host
# admits only their range) and WireGuard; from outside only WireGuard and ICMP.
resource "hcloud_firewall" "db" {
  name   = "db"
  labels = { platform = "odoo-cloud", role = "db" }

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

resource "hcloud_server" "db" {
  name               = "db-1"
  server_type        = var.db_server_type
  image              = var.image
  location           = var.location
  ssh_keys           = [for k in hcloud_ssh_key.operator : k.id]
  firewall_ids       = [hcloud_firewall.db.id]
  delete_protection  = true
  rebuild_protection = true
  backups            = false # L1 archives and L2 pgBackRest (DOC-05 §1)
  labels             = { platform = "odoo-cloud", role = "db" }

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  network {
    network_id = hcloud_network.platform.id
    ip         = var.db_private_ip
  }

  depends_on = [hcloud_network_subnet.hosts]

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [image, ssh_keys]
  }
}

# App hosts serve the tenants: HTTP (ACME, redirects) and HTTPS from anywhere, through Traefik.
resource "hcloud_firewall" "app" {
  name   = "app"
  labels = { platform = "odoo-cloud", role = "app" }

  dynamic "rule" {
    for_each = ["80", "443"]
    content {
      direction  = "in"
      protocol   = "tcp"
      port       = rule.value
      source_ips = ["0.0.0.0/0", "::/0"]
    }
  }

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

resource "hcloud_server" "app" {
  for_each           = var.app_hosts
  name               = each.key
  server_type        = each.value.server_type
  image              = var.image
  location           = var.location
  ssh_keys           = [for k in hcloud_ssh_key.operator : k.id]
  firewall_ids       = [hcloud_firewall.app.id]
  delete_protection  = true
  rebuild_protection = true
  backups            = false
  labels             = { platform = "odoo-cloud", role = "app" }

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  network {
    network_id = hcloud_network.platform.id
    ip         = each.value.private_ip
  }

  depends_on = [hcloud_network_subnet.hosts]

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [image, ssh_keys]
  }
}

# The tenants' filestore lives on a Volume, which survives losing the server (DOC-05 §1, §6.2
# amendment A1): a replacement host re-attaches it. Mounted and formatted by the app play.
resource "hcloud_volume" "filestore" {
  for_each          = var.app_hosts
  name              = "${each.key}-filestore"
  size              = each.value.volume_gb
  location          = var.location
  format            = "ext4"
  delete_protection = true
  labels            = { platform = "odoo-cloud", role = "filestore", host = each.key }

  lifecycle {
    prevent_destroy = true
  }
}

resource "hcloud_volume_attachment" "filestore" {
  for_each  = var.app_hosts
  volume_id = hcloud_volume.filestore[each.key].id
  server_id = hcloud_server.app[each.key].id
  automount = false
}
