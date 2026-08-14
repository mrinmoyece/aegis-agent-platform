resource "aws_security_group" "database" {
  name_prefix = "${local.name}-database-"
  description = "PostgreSQL from trusted application subnets only"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "PostgreSQL TLS from EKS workloads"
    protocol        = "tcp"
    from_port       = 5432
    to_port         = 5432
    security_groups = [aws_eks_cluster.this.vpc_config[0].cluster_security_group_id]
  }

  egress {
    description = "No internet egress; response traffic within VPC"
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = [var.vpc_cidr]
  }
}

resource "aws_db_subnet_group" "ledger" {
  name       = local.name
  subnet_ids = values(aws_subnet.data)[*].id
}

resource "aws_db_parameter_group" "ledger" {
  name   = "${local.name}-postgres16"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }
}

resource "aws_db_instance" "ledger" {
  identifier                    = "${local.name}-ledger"
  engine                        = "postgres"
  engine_version                = "16.8"
  instance_class                = var.database_instance_class
  allocated_storage             = 100
  max_allocated_storage         = 500
  storage_type                  = "gp3"
  storage_encrypted             = true
  kms_key_id                    = aws_kms_key.platform.arn
  db_name                       = "aegis"
  username                      = "aegis_admin"
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.platform.arn
  multi_az                      = true
  publicly_accessible           = false
  db_subnet_group_name          = aws_db_subnet_group.ledger.name
  parameter_group_name          = aws_db_parameter_group.ledger.name
  vpc_security_group_ids        = [aws_security_group.database.id]
  backup_retention_period       = 35
  backup_window                 = "02:00-03:00"
  maintenance_window            = "sun:03:30-sun:04:30"
  auto_minor_version_upgrade    = false
  deletion_protection           = var.environment == "production"
  skip_final_snapshot           = var.environment != "production"
  final_snapshot_identifier     = var.environment == "production" ? "${local.name}-final" : null
  copy_tags_to_snapshot         = true
  performance_insights_enabled  = true
  enabled_cloudwatch_logs_exports = [
    "postgresql",
    "upgrade",
  ]
}

resource "aws_security_group" "redis" {
  name_prefix = "${local.name}-redis-"
  description = "Redis transport from trusted application subnets only"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "Redis TLS from EKS workloads"
    protocol        = "tcp"
    from_port       = 6379
    to_port         = 6379
    security_groups = [aws_eks_cluster.this.vpc_config[0].cluster_security_group_id]
  }

  egress {
    description = "Response traffic within VPC"
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = [var.vpc_cidr]
  }
}

resource "aws_elasticache_subnet_group" "transport" {
  name       = local.name
  subnet_ids = values(aws_subnet.data)[*].id
}

resource "aws_elasticache_replication_group" "transport" {
  replication_group_id       = "${local.name}-transport"
  description                = "Non-authoritative at-least-once Redis transport"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = "cache.t4g.small"
  port                       = 6379
  parameter_group_name       = "default.redis7"
  subnet_group_name          = aws_elasticache_subnet_group.transport.name
  security_group_ids         = [aws_security_group.redis.id]
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled           = true
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  kms_key_id                 = aws_kms_key.platform.arn
  snapshot_retention_limit   = 1
  maintenance_window         = "sun:05:00-sun:06:00"
  auto_minor_version_upgrade = false
  apply_immediately          = false
}
