package aegisai.guardrails

import rego.v1

# Run with: docker run --rm -v "${PWD}/gateway/policy/rego:/policy" openpolicyagent/opa test /policy -v

test_read_customer_profile_has_no_hard_rule if {
	result.decision == "NONE" with input as {
		"agent_id": "customer-support-agent",
		"action": "read",
		"resource": "customer_db.profile",
		"record_count": 1,
		"data_classification": "INTERNAL",
		"destination": "internal",
	}
}

test_bulk_export_denied if {
	test_input := {
		"agent_id": "customer-support-agent",
		"action": "export",
		"resource": "customer_db.bulk",
		"record_count": 50000,
		"data_classification": "SENSITIVE",
		"destination": "external_api",
	}
	result.decision == "DENY" with input as test_input
	"deny_bulk_export" in result.matched_rules with input as test_input
}

test_secret_access_denied if {
	result.decision == "DENY" with input as {
		"agent_id": "customer-support-agent",
		"action": "read",
		"resource": "secrets.api_key",
		"record_count": 1,
		"data_classification": "HIGHLY_SENSITIVE",
		"destination": "internal",
	}
}

test_prod_delete_requires_approval if {
	result.decision == "HUMAN_APPROVAL" with input as {
		"agent_id": "data-ops-agent",
		"action": "delete",
		"resource": "database.production_orders",
		"record_count": 1,
		"data_classification": "HIGHLY_SENSITIVE",
		"destination": "internal",
	}
}

test_highly_sensitive_to_external_denied if {
	result.decision == "DENY" with input as {
		"agent_id": "billing-agent",
		"action": "read",
		"resource": "payments.account",
		"record_count": 1,
		"data_classification": "HIGHLY_SENSITIVE",
		"destination": "external_api",
	}
}

test_customer_support_cannot_write_customer_db if {
	result.decision == "DENY" with input as {
		"agent_id": "customer-support-agent",
		"action": "write",
		"resource": "customer_db.profile",
		"record_count": 1,
		"data_classification": "INTERNAL",
		"destination": "internal",
	}
}

test_deny_takes_precedence_over_approval_when_both_could_match if {
	# A read against a secret resource should DENY outright -- never fall
	# through toward an approval path just because some other field looks
	# sensitive.
	result.decision == "DENY" with input as {
		"agent_id": "data-ops-agent",
		"action": "read",
		"resource": "secrets.database_password",
		"record_count": 1,
		"data_classification": "HIGHLY_SENSITIVE",
		"destination": "internal",
	}
}
