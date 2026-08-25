variable "aws_region" {
  description = "Single authoritative writer region for this environment."
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Environment boundary; use a distinct account and state per value."
  type        = string
  default     = "development"

  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be development, staging, or production."
  }
}

variable "owner" {
  description = "Cost and operational ownership tag."
  type        = string
  default     = "platform-engineering"
}

variable "enable_reference_environment" {
  description = "Explicit paid-resource gate. CI leaves this false and uses mocked plans."
  type        = bool
  default     = false
}

variable "vpc_cidr" {
  description = "Private VPC range; do not overlap connected networks."
  type        = string
  default     = "10.42.0.0/16"
}

variable "kubernetes_version" {
  description = "EKS control-plane and node Kubernetes version."
  type        = string
  default     = "1.32"
}

variable "coredns_addon_version" {
  description = "Pinned CoreDNS EKS add-on version qualified with the cluster version."
  type        = string
  default     = "v1.11.4-eksbuild.2"
}

variable "kube_proxy_addon_version" {
  description = "Pinned kube-proxy EKS add-on version qualified with the cluster version."
  type        = string
  default     = "v1.32.0-eksbuild.2"
}

variable "pod_identity_addon_version" {
  description = "Pinned EKS Pod Identity Agent add-on version."
  type        = string
  default     = "v1.3.4-eksbuild.1"
}

variable "vpc_cni_addon_version" {
  description = "Pinned VPC CNI add-on version with NetworkPolicy enforcement enabled."
  type        = string
  default     = "v1.19.2-eksbuild.1"
}

variable "node_ami_type" {
  description = "Managed-node AMI architecture; must match every configured instance type."
  type        = string
  default     = "AL2023_ARM_64_STANDARD"

  validation {
    condition = contains(
      ["AL2023_ARM_64_STANDARD", "AL2023_x86_64_STANDARD"],
      var.node_ami_type,
    )
    error_message = "Node AMI type must be an approved AL2023 standard architecture."
  }
}

variable "database_instance_class" {
  description = "Cost-conscious reference RDS instance class."
  type        = string
  default     = "db.t4g.medium"
}

variable "system_node_instance_types" {
  description = "Instance types for trusted system workloads."
  type        = list(string)
  default     = ["m7g.large"]
}

variable "sandbox_node_instance_types" {
  description = "Dedicated tainted node pool for untrusted sandbox jobs."
  type        = list(string)
  default     = ["m7g.large"]
}

variable "route53_zone_id" {
  description = "Optional pre-existing public hosted-zone ID for TLS validation."
  type        = string
  default     = ""
}

variable "public_domain" {
  description = "Optional environment domain, for example aegis.example.com."
  type        = string
  default     = ""
}

variable "external_secret_arns" {
  description = "Pre-created connector/OIDC secret ARNs readable through workload identity."
  type        = list(string)
  default     = []
}

variable "external_secret_kms_key_arns" {
  description = "Optional customer-managed KMS keys used by approved external secrets."
  type        = list(string)
  default     = []
}

variable "eks_admin_principal_arn" {
  description = "Reviewed IAM role ARN granted explicit EKS cluster administration."
  type        = string
  default     = ""
}
