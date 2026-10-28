output "ctl_public_ipv4" {
  value = hcloud_server.ctl.ipv4_address
}

output "ctl_public_ipv6" {
  value = hcloud_server.ctl.ipv6_address
}

output "ctl_private_ip" {
  value = var.ctl_private_ip
}

output "network_id" {
  description = "For db-1 and the app hosts."
  value       = hcloud_network.platform.id
}

output "db_public_ipv4" {
  value = hcloud_server.db.ipv4_address
}

output "app_hosts" {
  description = "name => {public_ipv4, private_ip, filestore_volume_id (its device: /dev/disk/by-id/scsi-0HC_Volume_<id>)}"
  value = { for name, s in hcloud_server.app : name => {
    public_ipv4         = s.ipv4_address
    private_ip          = var.app_hosts[name].private_ip
    filestore_volume_id = hcloud_volume.filestore[name].id
  } }
}
