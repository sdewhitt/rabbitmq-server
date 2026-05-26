PROJECT = rabbitmq_auth_validation
PROJECT_DESCRIPTION = RabbitMQ Auth Backend Configuration Validation
PROJECT_MOD = rabbit_auth_validation_app

define PROJECT_ENV
[
    {enabled_methods,        [<<"ldap-simple-bind">>]},
    {max_body_size,          65536},
    {max_concurrent,         5},
    {connection_timeout_ms,  5000},
    {rate_limit_window_ms,   60000},
    {rate_limit_max_requests, 10},
    {required_user_tag,      administrator}
  ]
endef

define PROJECT_APP_EXTRA_KEYS
	{broker_version_requirements, []}
endef

LOCAL_DEPS = eldap public_key
DEPS = rabbit_common rabbit rabbitmq_management cuttlefish
TEST_DEPS = rabbitmq_ct_helpers rabbitmq_ct_client_helpers amqp_client

DEP_EARLY_PLUGINS = rabbit_common/mk/rabbitmq-early-plugin.mk
DEP_PLUGINS = rabbit_common/mk/rabbitmq-plugin.mk

include ../../rabbitmq-components.mk
include ../../erlang.mk
