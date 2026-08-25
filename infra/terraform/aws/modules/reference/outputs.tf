output "cluster_name" {
  value = aws_eks_cluster.this.name
}

output "artifact_bucket_name" {
  value = aws_s3_bucket.artifacts.bucket
}

output "backup_vault_name" {
  value = aws_backup_vault.this.name
}

output "database_managed_secret_arn" {
  value = aws_db_instance.ledger.master_user_secret[0].secret_arn
}

output "runtime_role_arn" {
  value = aws_iam_role.runtime.arn
}

output "ecr_repository_urls" {
  value = {
    for name, repository in aws_ecr_repository.application :
    name => repository.repository_url
  }
}
