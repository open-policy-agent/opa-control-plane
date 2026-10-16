package object

import rego.v1

sample_package := "car_info_store"

actions := data.global.systemtypes["entitlements:1.0"].library.sample[sample_package].actions

resources := data.global.systemtypes["entitlements:1.0"].library.sample[sample_package].resources

roles := data.global.systemtypes["entitlements:1.0"].library.sample[sample_package].roles

role_bindings := data.global.systemtypes["entitlements:1.0"].library.sample[sample_package].role_bindings

users := data.global.systemtypes["entitlements:1.0"].library.sample[sample_package].users

groups := data.global.systemtypes["entitlements:1.0"].library.sample[sample_package].groups

service_accounts := {}
