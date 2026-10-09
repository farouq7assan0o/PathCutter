# Terraform for the corp directory and the Entra tenant
variable "ops_group" {
  default = "Helpdesk"
}

locals {
  breakglass = "svc_break"
}

resource "ad_user" "new_hire" {
  principal_name   = "newhire@corp.local"
  sam_account_name = "newhire"
}

resource "ad_group" "deploy" {
  name = "Deployers"
}

resource "ad_group_membership" "helpdesk" {
  group_id      = var.ops_group
  group_members = [ad_user.new_hire.sam_account_name, "alice", local.breakglass]
}

resource "ad_group_membership" "da" {
  group_id      = "CN=Domain Admins,CN=Users,DC=corp,DC=local"
  group_members = ["CORP\\bob"]
}

resource "azuread_user" "ada" {
  user_principal_name = "ada@corp.com"
  display_name        = "Ada"
}

resource "azuread_directory_role_assignment" "ga" {
  role_id             = "62e90394-69f5-4237-9190-012177145e10"
  principal_object_id = azuread_user.ada.object_id
}

resource "azuread_group_owner" "own" {
  group_object_id = "g-cloud-admins"
  owner_object_id = "bob@corp.com"
}

resource "ad_group_membership" "dynamic" {
  for_each      = toset(["x", "y"])
  group_id      = "Helpdesk"
  group_members = [each.value]
}

resource "ad_group_membership" "computed" {
  group_id      = "Helpdesk"
  group_members = [data.external.who.result.user]
}

resource "azuread_conditional_access_policy" "ca" {
  display_name = "Require MFA"
}

resource "ad_gpo" "baseline" {
  name = "Baseline"
}

/* block comment with = and { braces } inside */
resource "ad_group_membership" "heredoc_user" {
  group_id      = "Helpdesk"
  group_members = ["carol"] // trailing comment
  description   = <<-EOT
    this text has "quotes", = signs and ${interpolation} inside
  EOT
}
