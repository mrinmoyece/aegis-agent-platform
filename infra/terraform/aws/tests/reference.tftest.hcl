mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111122223333"
      arn        = "arn:aws:iam::111122223333:root"
      user_id    = "111122223333"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }
}

run "cost_gate_is_off_by_default" {
  command = plan

  assert {
    condition     = length(module.reference) == 0
    error_message = "paid reference resources must be disabled by default"
  }
}

run "production_reference_is_private_and_encrypted" {
  command = plan

  variables {
    enable_reference_environment = true
    environment                  = "production"
    eks_admin_principal_arn      = "arn:aws:iam::111122223333:role/aegis-platform-administrator"
    route53_zone_id              = "Z111122223333"
    public_domain                = "aegis.example.com"
  }

  assert {
    condition     = module.reference[0].cluster_name == "aegis-production"
    error_message = "production cluster naming drifted"
  }
}

run "production_reference_without_dns_is_blocked" {
  command = plan

  variables {
    enable_reference_environment = true
    environment                  = "production"
    eks_admin_principal_arn      = "arn:aws:iam::111122223333:role/aegis-platform-administrator"
  }

  expect_failures = [terraform_data.input_guardrails]
}
