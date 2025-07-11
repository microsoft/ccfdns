package platform_relying_party_policy
import rego.v1

# Given as input a TEE attestation and a list of supporting statements, 
# validates that its attestation meets the platform requirements for this named service. 
#
# This policy is defined by the platform owner. 

zone := `attested.name` 

valid_fqdn_in_zone(name) if {
    # Check overall length (253 chars max)
    count(name) <= 253
    
    # Check pattern (each label 61 chars max)
    dns_label := `[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?`
    dns_pattern := concat("", ["^(", dns_label, `\.)*`, dns_label, "\.", zone, "$"])
    regex.match(dns_pattern, name)
    
    # Ensure not all numeric (for root level)
    not regex.match(`^[0-9.]+$`, name)
}

well_formed_input if {
    input.utc_time 
    input.attestation.time  
    input.attestation.code
    input.attestation.platform_certificate
    input.attestation.host_data.hostname	
}

valid_uvm_digests := [
    "0xABCDEF123456...",
    "0x987654FEDCBA..."
]

valid_platform_certificates := [
    "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
]

default allow := false 

allow if {
	well_formed_input 

	# The TEE registers within the zone 
	hostname := lower(input.attestation.host_data.hostname)
    valid_fqdn_in_zone(hostname)
    
    # The TEE runs on a valid platform 
    input.attestation.code in valid_uvm_digests 
    input.attestation.platform_certificate in valid_platform_certificates

    # The attestation is reasonably fresh   
    input.attestation.time + 3600 >= input.utc_time
}

