output "cluster_name" {
  description = "EKS cluster name; null when the paid-resource gate is disabled."
  value       = try(module.reference[0].cluster_name, null)
}

output "artifact_bucket_name" {
  description = "Encrypted artifact bucket name."
  value       = try(module.reference[0].artifact_bucket_name, null)
}

output "backup_vault_name" {
  description = "Locked AWS Backup vault name."
  value       = try(module.reference[0].backup_vault_name, null)
}

output "database_managed_secret_arn" {
  description = "Reference only; secret values are never Terraform outputs."
  value       = try(module.reference[0].database_managed_secret_arn, null)
}

output "runtime_role_arn" {
  description = "EKS Pod Identity role for tenant-bound runtime secret and object access."
  value       = try(module.reference[0].runtime_role_arn, null)
}

output "ecr_repository_urls" {
  description = "Private immutable repositories used by promotion and controller mirroring."
  value       = try(module.reference[0].ecr_repository_urls, {})
}
