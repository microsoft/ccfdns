package service_registration_policy
import rego.v1

# Given as input a policy statement for named service, 
# registers its payload as the TEE registration for this service.
#
# This policy is defined by the aDNS service owner. 

well_formed_input if {
    input.header
    input.header["iss"]
    input.header["sub"] 
    input.header["svn"]
    input.header["time"]
    input.service
}

iss := input.header["iss"] if well_formed_input
sub := input.header["sub"] if well_formed_input

valid_subject if 
  sub == concat(":",["service rp policy", input.service])

check_svn(previous) if {
  svn := to_number(input.header["svn"])
  time := to_number(input.header["time"])
  svn >= to_number(previous.svn)
  time >= to_number(previous.time)
}

valid_issuer if {
  old_policy := data.registered_services[input.service]
  iss == old_policy.header["iss"]
  check_svn(old_policy)
} else if {
  known_service := data.wellknown_services[input.service]
  iss == known_service.header.iss
  check_svn(known_service)
} else if {
  not data.registered_services[input.service]
  not data.wellknown_services[input.service]
}

allow if {
  well_formed_input
  valid_issuer
  valid_subject
}
