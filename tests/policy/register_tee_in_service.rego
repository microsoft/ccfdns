package service_relying_party_policy
import rego.v1

# Given as input a TEE attestation and a list of supporting statements, 
# validates that a TEE "speaks for" a named service. 
#
# This policy is defined by the service owner. 
#
# Policy evaluation may fail with an error on bad inputs. 

well_formed_input if {
    input.attestation
    input.attestation.host_data
    input.attestation.host_data.hostname
    input.attestation.cce_policy_digest	
}

service := `service`
zone := `attested.name` 

# a single alphanumeric label 
role := `[[:alpha:]][[:alnum:]]*`

# a simpler example with a fixed label 
# function := `www` 

fqdn := concat("", [ "^", role, "\.", service, "\.", zone, "$"])

cce_policy_v1_1 := "0xABC..."
cce_policy_v2_0 := "0xACE..."

valid_cce_policy_digests := [cce_policy_v1_1, cce_policy_v2_0]

default allow := false 

allow if {
	well_formed_input 

	# The TEE registers at a name of the form *.service.zone
	hostname := lower(input.attestation.host_data.hostname)
    regex.match(fqdn, hostname)
    
    # The TEE has runs with a valid code identity for the service. 
    input.attestation.cce_policy_digest in valid_cce_policy_digests
}
