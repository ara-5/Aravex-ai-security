package aegisai.guardrails

import rego.v1

# The same hard guardrails as gateway/policy/rules.yaml, expressed as real
# policy-as-code and evaluated by a real OPA server instead of a hand-rolled
# Python rule matcher. This is the "production" path: gateway/policy/engine.py
# calls this via gateway/policy/opa_client.py when OPA_URL is configured, and
# falls back to the local YAML rule engine when it isn't -- so the simple
# `uvicorn --reload` quickstart still works with zero extra infrastructure.
#
# Exercise it directly:
#   docker run --rm -v "${PWD}/gateway/policy/rego:/policy" openpolicyagent/opa test /policy -v

rule_reasons := {
	"deny_secret_access": "Agents may never read or export secrets/credentials through the gateway.",
	"deny_bulk_export": "Bulk export exceeds the maximum record threshold allowed for automated agents.",
	"block_highly_sensitive_to_external": "Highly sensitive data may not leave the perimeter through an external API.",
	"deny_customer_support_db_write": "customer-support-agent is scoped to read-only access on customer_db.",
	"require_approval_prod_delete": "Deleting production data always requires explicit human sign-off.",
}

deny_rule_names := {
	"deny_secret_access",
	"deny_bulk_export",
	"block_highly_sensitive_to_external",
	"deny_customer_support_db_write",
}

approval_rule_names := {"require_approval_prod_delete"}

matched_rules contains name if {
	name := "deny_secret_access"
	contains(lower(input.resource), "secrets.")
}

matched_rules contains name if {
	name := "deny_secret_access"
	contains(lower(input.resource), "api_key")
}

matched_rules contains name if {
	name := "deny_secret_access"
	contains(lower(input.resource), "credential")
}

matched_rules contains name if {
	name := "deny_bulk_export"
	input.action == "export"
	input.record_count > 1000
}

matched_rules contains name if {
	name := "block_highly_sensitive_to_external"
	input.data_classification == "HIGHLY_SENSITIVE"
	input.destination == "external_api"
}

matched_rules contains name if {
	name := "deny_customer_support_db_write"
	input.agent_id == "customer-support-agent"
	input.action == "write"
	startswith(input.resource, "customer_db.")
}

matched_rules contains name if {
	name := "require_approval_prod_delete"
	input.action == "delete"
	contains(lower(input.resource), "database")
}

matched_rules contains name if {
	name := "require_approval_prod_delete"
	input.action == "delete"
	contains(lower(input.resource), "production")
}

# Rules generated from red-team findings (see gateway/policy/rego_export.py)
# are pushed to OPA as a separate policy in this same package. They add to
# these three partial sets; the empty declarations below keep the references
# well-defined when nothing has been pushed.
generated_deny contains name if {
	name := ""
	false
}

generated_approval contains name if {
	name := ""
	false
}

generated_reasons[name] := reason if {
	name := ""
	reason := ""
	false
}

matched_rules contains name if some name in generated_deny

matched_rules contains name if some name in generated_approval

deny_matched := (matched_rules & deny_rule_names) | generated_deny

approval_matched := (matched_rules & approval_rule_names) | generated_approval

decision := "DENY" if {
	count(deny_matched) > 0
} else := "HUMAN_APPROVAL" if {
	count(approval_matched) > 0
} else := "NONE" if {
	true
}

reasons contains r if {
	some name in matched_rules
	r := sprintf("rule '%s': %s", [name, rule_reasons[name]])
}

reasons contains r if {
	some name in matched_rules
	r := sprintf("rule '%s': %s", [name, generated_reasons[name]])
}

result := {
	"decision": decision,
	"matched_rules": matched_rules,
	"reasons": reasons,
}
