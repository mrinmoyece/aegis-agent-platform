data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  name = "aegis-${var.environment}"
  azs  = slice(data.aws_availability_zones.available.names, 0, 2)
}
