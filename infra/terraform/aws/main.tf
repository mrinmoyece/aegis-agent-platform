module "reference" {
  count  = var.enable_reference_environment ? 1 : 0
  source = "./modules/reference"

  aws_region                   = var.aws_region
  database_instance_class      = var.database_instance_class
  environment                  = var.environment
  eks_admin_principal_arn      = var.eks_admin_principal_arn
  external_secret_arns         = var.external_secret_arns
  external_secret_kms_key_arns = var.external_secret_kms_key_arns
  kubernetes_version           = var.kubernetes_version
  coredns_addon_version        = var.coredns_addon_version
  kube_proxy_addon_version     = var.kube_proxy_addon_version
  pod_identity_addon_version   = var.pod_identity_addon_version
  vpc_cni_addon_version        = var.vpc_cni_addon_version
  node_ami_type                = var.node_ami_type
  public_domain                = var.public_domain
  route53_zone_id              = var.route53_zone_id
  sandbox_node_instance_types  = var.sandbox_node_instance_types
  system_node_instance_types   = var.system_node_instance_types
  vpc_cidr                     = var.vpc_cidr
}

resource "terraform_data" "input_guardrails" {
  input = {
    enable_reference_environment = var.enable_reference_environment
    environment                  = var.environment
  }

  lifecycle {
    precondition {
      condition = (
        var.environment != "production"
        || !var.enable_reference_environment
        || (var.route53_zone_id != "" && var.public_domain != "")
      )
      error_message = "production apply requires explicit Route53 and public-domain inputs"
    }

    precondition {
      condition = (
        !var.enable_reference_environment
        || can(regex("^arn:aws:iam::[0-9]{12}:role/.+", var.eks_admin_principal_arn))
      )
      error_message = "enabled reference environment requires an explicit EKS administrator role ARN"
    }
  }
}
