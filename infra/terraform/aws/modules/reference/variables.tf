variable "aws_region" {
  type = string
}

variable "environment" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "kubernetes_version" {
  type = string
}

variable "coredns_addon_version" {
  type = string
}

variable "kube_proxy_addon_version" {
  type = string
}

variable "pod_identity_addon_version" {
  type = string
}

variable "vpc_cni_addon_version" {
  type = string
}

variable "node_ami_type" {
  type = string
}

variable "database_instance_class" {
  type = string
}

variable "system_node_instance_types" {
  type = list(string)
}

variable "sandbox_node_instance_types" {
  type = list(string)
}

variable "route53_zone_id" {
  type = string
}

variable "public_domain" {
  type = string
}

variable "external_secret_arns" {
  type = list(string)
}

variable "external_secret_kms_key_arns" {
  type = list(string)
}

variable "eks_admin_principal_arn" {
  type = string
}
