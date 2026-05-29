%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.

-module(auth_validation_ldap_SUITE).
-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("rabbitmq_ct_helpers/include/rabbit_mgmt_test.hrl").

-define(UNPROCESSABLE_ENTITY, 422).
-define(LDAP_PORT, 25389).
-define(BASE_DN, "dc=rabbitmq,dc=com").
-define(ALICE_DN, "cn=Alice,ou=People," ?BASE_DN).
-define(ALICE_PASSWORD, "password").
-define(ENDPOINT, "/auth/validate/ldap-simple-bind").

%%--------------------------------------------------------------------
%% CT callbacks
%%--------------------------------------------------------------------

all() ->
    [{group, integration_tests}].

groups() ->
    [{integration_tests, [],
      [valid_bind_plaintext,
       valid_bind_admin,
       wrong_password,
       wrong_dn,
       nonexistent_user,
       empty_password_rejected,
       empty_dn_rejected,
       unreachable_server,
       wrong_port,
       config_conflict_ssl_and_starttls,
       missing_servers_field,
       missing_password_field,
       missing_user_dn_field,
       invalid_port_type,
       invalid_port_range,
       servers_not_a_list,
       unknown_method_returns_404,
       disabled_method_returns_404,
       wrong_http_verb_get,
       wrong_http_verb_post,
       wrong_http_verb_delete,
       unauthenticated_request,
       rate_limit_enforcement,
       semaphore_exhaustion,
       field_filtering,
       oversized_body_rejected,
       invalid_json_rejected,
       non_object_body_rejected
      ]}].

init_per_suite(Config) ->
    rabbit_ct_helpers:log_environment(),
    Config1 = rabbit_ct_helpers:run_setup_steps(Config, [fun init_slapd/1]),
    rabbit_ct_helpers:set_config(Config1, [{ldap_port, ?LDAP_PORT}]).

end_per_suite(Config) ->
    rabbit_ct_helpers:run_teardown_steps(Config, [fun stop_slapd/1]).

init_per_group(_Group, Config) ->
    Config1 = rabbit_ct_helpers:set_config(Config, [
        {rmq_nodename_suffix, auth_validation}
    ]),
    Config2 = rabbit_ct_helpers:merge_app_env(Config1,
        {rabbit, [{default_vhost, <<"/">>}]}),
    Config3 = rabbit_ct_helpers:merge_app_env(Config2,
        {rabbitmq_auth_validation, [
            {enabled_methods, [<<"ldap-simple-bind">>]},
            {max_body_size, 65536},
            {max_concurrent, 2},
            {connection_timeout_ms, 5000},
            {rate_limit_window_ms, 60000},
            {rate_limit_max_requests, 5},
            {required_user_tag, administrator}
        ]}),
    LdapPort = ?config(ldap_port, Config3),
    seed_ldap(LdapPort),
    rabbit_ct_helpers:run_steps(Config3,
        rabbit_ct_broker_helpers:setup_steps() ++
        rabbit_ct_client_helpers:setup_steps()).

end_per_group(_Group, Config) ->
    LdapPort = ?config(ldap_port, Config),
    delete_ldap(LdapPort),
    rabbit_ct_helpers:run_steps(Config,
        rabbit_ct_client_helpers:teardown_steps() ++
        rabbit_ct_broker_helpers:teardown_steps()).

init_per_testcase(rate_limit_enforcement, Config) ->
    rabbit_ct_broker_helpers:rpc(Config, 0,
        rabbit_auth_validation_rate_limiter, reset, []),
    rabbit_ct_helpers:testcase_started(Config, rate_limit_enforcement);
init_per_testcase(Testcase, Config) ->
    rabbit_ct_helpers:testcase_started(Config, Testcase).

end_per_testcase(Testcase, Config) ->
    rabbit_ct_helpers:testcase_finished(Config, Testcase).

%%--------------------------------------------------------------------
%% LDAP setup / teardown
%%--------------------------------------------------------------------

init_slapd(Config) ->
    DataDir = ?config(data_dir, Config),
    PrivDir = ?config(priv_dir, Config),
    SlapdDir = filename:join([PrivDir, "openldap"]),
    InitSlapd = filename:join([DataDir, "init-slapd.sh"]),
    Cmd = [InitSlapd, SlapdDir, {"~b", [?LDAP_PORT]}],
    case rabbit_ct_helpers:exec(Cmd) of
        {ok, Stdout} ->
            {match, [SlapdPid]} = re:run(
                Stdout,
                "^SLAPD_PID=([0-9]+)$",
                [{capture, all_but_first, list}, multiline]),
            ct:pal("slapd PID: ~ts, port: ~b", [SlapdPid, ?LDAP_PORT]),
            rabbit_ct_helpers:set_config(Config, [{slapd_pid, SlapdPid}]);
        _ ->
            _ = rabbit_ct_helpers:exec(["pkill", "-INT", "slapd"]),
            {skip, "Failed to initialize slapd"}
    end.

stop_slapd(Config) ->
    case ?config(slapd_pid, Config) of
        undefined -> ok;
        "0" -> ok;
        Pid -> rabbit_ct_helpers:exec(["kill", "-INT", Pid])
    end,
    Config.

seed_ldap(Port) ->
    {ok, H} = eldap:open(["localhost"], [{port, Port}]),
    ok = eldap:simple_bind(H, "cn=admin," ?BASE_DN, "admin"),
    add_ignore_exists(H, {?BASE_DN,
        [{"objectClass", ["dcObject", "organization"]},
         {"dc", ["rabbitmq"]},
         {"o", ["Test"]}]}),
    add_ignore_exists(H, {"ou=People," ?BASE_DN,
        [{"objectClass", ["organizationalUnit"]},
         {"ou", ["People"]}]}),
    add_ignore_exists(H, {?ALICE_DN,
        [{"objectClass", ["person"]},
         {"cn", ["Alice"]},
         {"sn", ["Test"]},
         {"userPassword", [?ALICE_PASSWORD]}]}),
    add_ignore_exists(H, {"cn=Bob,ou=People," ?BASE_DN,
        [{"objectClass", ["person"]},
         {"cn", ["Bob"]},
         {"sn", ["Builder"]},
         {"userPassword", ["bobpass"]}]}),
    eldap:close(H),
    ok.

delete_ldap(Port) ->
    {ok, H} = eldap:open(["localhost"], [{port, Port}]),
    ok = eldap:simple_bind(H, "cn=admin," ?BASE_DN, "admin"),
    _ = eldap:delete(H, "cn=Bob,ou=People," ?BASE_DN),
    _ = eldap:delete(H, ?ALICE_DN),
    _ = eldap:delete(H, "ou=People," ?BASE_DN),
    _ = eldap:delete(H, ?BASE_DN),
    eldap:close(H),
    ok.

add_ignore_exists(H, {DN, Attrs}) ->
    case eldap:add(H, DN, Attrs) of
        ok -> ok;
        {error, entryAlreadyExists} -> ok
    end.

%%--------------------------------------------------------------------
%% Happy path tests
%%--------------------------------------------------------------------

valid_bind_plaintext(Config) ->
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => list_to_binary(?ALICE_DN),
        <<"password">> => list_to_binary(?ALICE_PASSWORD)
    },
    ?NO_CONTENT = api_put(Config, ?ENDPOINT, Body).

valid_bind_admin(Config) ->
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => <<"cn=admin,dc=rabbitmq,dc=com">>,
        <<"password">> => <<"admin">>
    },
    ?NO_CONTENT = api_put(Config, ?ENDPOINT, Body).

%%--------------------------------------------------------------------
%% Authentication failure tests
%%--------------------------------------------------------------------

wrong_password(Config) ->
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => list_to_binary(?ALICE_DN),
        <<"password">> => <<"wrong-password">>
    },
    {?UNPROCESSABLE_ENTITY, RespBody} = api_put_with_body(Config, ?ENDPOINT, Body),
    ?assertEqual(<<"auth_failed">>, maps:get(<<"error">>, RespBody)).

wrong_dn(Config) ->
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => <<"cn=NonExistent,ou=People,dc=rabbitmq,dc=com">>,
        <<"password">> => <<"password">>
    },
    {?UNPROCESSABLE_ENTITY, RespBody} = api_put_with_body(Config, ?ENDPOINT, Body),
    ?assertEqual(<<"auth_failed">>, maps:get(<<"error">>, RespBody)).

nonexistent_user(Config) ->
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => <<"cn=Ghost,ou=Nobody,dc=rabbitmq,dc=com">>,
        <<"password">> => <<"password">>
    },
    {?UNPROCESSABLE_ENTITY, RespBody} = api_put_with_body(Config, ?ENDPOINT, Body),
    ?assertEqual(<<"auth_failed">>, maps:get(<<"error">>, RespBody)).

empty_password_rejected(Config) ->
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => list_to_binary(?ALICE_DN),
        <<"password">> => <<>>
    },
    {?BAD_REQUEST, RespBody} = api_put_with_body(Config, ?ENDPOINT, Body),
    ?assertEqual(<<"input_invalid">>, maps:get(<<"error">>, RespBody)).

empty_dn_rejected(Config) ->
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => <<>>,
        <<"password">> => <<"password">>
    },
    {?BAD_REQUEST, RespBody} = api_put_with_body(Config, ?ENDPOINT, Body),
    ?assertEqual(<<"input_invalid">>, maps:get(<<"error">>, RespBody)).

%%--------------------------------------------------------------------
%% Connection failure tests
%%--------------------------------------------------------------------

unreachable_server(Config) ->
    Body = #{
        <<"servers">> => [<<"192.0.2.1">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => list_to_binary(?ALICE_DN),
        <<"password">> => <<"password">>
    },
    {?BAD_REQUEST, RespBody} = api_put_with_body(Config, ?ENDPOINT, Body),
    ?assertEqual(<<"connection_failed">>, maps:get(<<"error">>, RespBody)).

wrong_port(Config) ->
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => 19999,
        <<"user_dn">> => list_to_binary(?ALICE_DN),
        <<"password">> => <<"password">>
    },
    {?BAD_REQUEST, RespBody} = api_put_with_body(Config, ?ENDPOINT, Body),
    ?assertEqual(<<"connection_failed">>, maps:get(<<"error">>, RespBody)).

%%--------------------------------------------------------------------
%% Config conflict tests
%%--------------------------------------------------------------------

config_conflict_ssl_and_starttls(Config) ->
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => list_to_binary(?ALICE_DN),
        <<"password">> => <<"password">>,
        <<"use_ssl">> => true,
        <<"use_starttls">> => true
    },
    {?UNPROCESSABLE_ENTITY, RespBody} = api_put_with_body(Config, ?ENDPOINT, Body),
    ?assertEqual(<<"config_conflict">>, maps:get(<<"error">>, RespBody)).

%%--------------------------------------------------------------------
%% Input validation tests
%%--------------------------------------------------------------------

missing_servers_field(Config) ->
    Body = #{
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => list_to_binary(?ALICE_DN),
        <<"password">> => <<"password">>
    },
    {?BAD_REQUEST, RespBody} = api_put_with_body(Config, ?ENDPOINT, Body),
    ?assertEqual(<<"input_invalid">>, maps:get(<<"error">>, RespBody)).

missing_password_field(Config) ->
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => list_to_binary(?ALICE_DN)
    },
    {?BAD_REQUEST, RespBody} = api_put_with_body(Config, ?ENDPOINT, Body),
    ?assertEqual(<<"input_invalid">>, maps:get(<<"error">>, RespBody)).

missing_user_dn_field(Config) ->
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"password">> => <<"password">>
    },
    {?BAD_REQUEST, RespBody} = api_put_with_body(Config, ?ENDPOINT, Body),
    ?assertEqual(<<"input_invalid">>, maps:get(<<"error">>, RespBody)).

invalid_port_type(Config) ->
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => <<"not-a-number">>,
        <<"user_dn">> => list_to_binary(?ALICE_DN),
        <<"password">> => <<"password">>
    },
    {?BAD_REQUEST, RespBody} = api_put_with_body(Config, ?ENDPOINT, Body),
    ?assertEqual(<<"input_invalid">>, maps:get(<<"error">>, RespBody)).

invalid_port_range(Config) ->
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => 99999,
        <<"user_dn">> => list_to_binary(?ALICE_DN),
        <<"password">> => <<"password">>
    },
    {?BAD_REQUEST, RespBody} = api_put_with_body(Config, ?ENDPOINT, Body),
    ?assertEqual(<<"input_invalid">>, maps:get(<<"error">>, RespBody)).

servers_not_a_list(Config) ->
    Body = #{
        <<"servers">> => <<"not-a-list">>,
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => list_to_binary(?ALICE_DN),
        <<"password">> => <<"password">>
    },
    {?BAD_REQUEST, RespBody} = api_put_with_body(Config, ?ENDPOINT, Body),
    ?assertEqual(<<"input_invalid">>, maps:get(<<"error">>, RespBody)).

%%--------------------------------------------------------------------
%% Method routing tests
%%--------------------------------------------------------------------

unknown_method_returns_404(Config) ->
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => <<"cn=test">>,
        <<"password">> => <<"test">>
    },
    404 = api_put(Config, "/auth/validate/oauth-token", Body).

disabled_method_returns_404(Config) ->
    rabbit_ct_broker_helpers:rpc(Config, 0,
        application, set_env,
        [rabbitmq_auth_validation, enabled_methods, []]),
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => list_to_binary(?ALICE_DN),
        <<"password">> => <<"password">>
    },
    404 = api_put(Config, ?ENDPOINT, Body),
    rabbit_ct_broker_helpers:rpc(Config, 0,
        application, set_env,
        [rabbitmq_auth_validation, enabled_methods, [<<"ldap-simple-bind">>]]).

%%--------------------------------------------------------------------
%% HTTP method enforcement tests
%%--------------------------------------------------------------------

wrong_http_verb_get(Config) ->
    ?METHOD_NOT_ALLOWED = api_get_status(Config, ?ENDPOINT).

wrong_http_verb_post(Config) ->
    ?METHOD_NOT_ALLOWED = api_post_status(Config, ?ENDPOINT, #{}).

wrong_http_verb_delete(Config) ->
    ?METHOD_NOT_ALLOWED = api_delete_status(Config, ?ENDPOINT).

%%--------------------------------------------------------------------
%% Authentication / authorization tests
%%--------------------------------------------------------------------

unauthenticated_request(Config) ->
    ?NOT_AUTHORISED = api_put_no_auth(Config, ?ENDPOINT, #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => <<"cn=test">>,
        <<"password">> => <<"test">>
    }).

%%--------------------------------------------------------------------
%% Rate limiting tests
%%--------------------------------------------------------------------

rate_limit_enforcement(Config) ->
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => list_to_binary(?ALICE_DN),
        <<"password">> => list_to_binary(?ALICE_PASSWORD)
    },
    %% Max is configured to 5 in init_per_group
    lists:foreach(fun(_) ->
        ?NO_CONTENT = api_put(Config, ?ENDPOINT, Body)
    end, lists:seq(1, 5)),
    %% The 6th request should be rate limited
    429 = api_put(Config, ?ENDPOINT, Body).

%%--------------------------------------------------------------------
%% Semaphore tests
%%--------------------------------------------------------------------

semaphore_exhaustion(Config) ->
    %% Max concurrent is 2. We occupy both slots via RPC, then verify
    %% the endpoint returns 503.
    {ok, T1} = rabbit_ct_broker_helpers:rpc(Config, 0,
        rabbit_auth_validation_semaphore, acquire, []),
    {ok, T2} = rabbit_ct_broker_helpers:rpc(Config, 0,
        rabbit_auth_validation_semaphore, acquire, []),
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => list_to_binary(?ALICE_DN),
        <<"password">> => list_to_binary(?ALICE_PASSWORD)
    },
    503 = api_put(Config, ?ENDPOINT, Body),
    %% Release and verify recovery
    rabbit_ct_broker_helpers:rpc(Config, 0,
        rabbit_auth_validation_semaphore, release, [T1]),
    rabbit_ct_broker_helpers:rpc(Config, 0,
        rabbit_auth_validation_semaphore, release, [T2]),
    ?NO_CONTENT = api_put(Config, ?ENDPOINT, Body).

%%--------------------------------------------------------------------
%% Field filtering tests
%%--------------------------------------------------------------------

field_filtering(Config) ->
    %% Unknown fields should be stripped and not cause errors
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => list_to_binary(?ALICE_DN),
        <<"password">> => list_to_binary(?ALICE_PASSWORD),
        <<"unknown_field">> => <<"should be stripped">>,
        <<"another_bogus">> => 42
    },
    ?NO_CONTENT = api_put(Config, ?ENDPOINT, Body).

%%--------------------------------------------------------------------
%% Body validation tests
%%--------------------------------------------------------------------

oversized_body_rejected(Config) ->
    %% Generate a body larger than 65536 bytes
    LargeValue = list_to_binary(lists:duplicate(70000, $x)),
    Body = #{
        <<"servers">> => [<<"localhost">>],
        <<"port">> => ?LDAP_PORT,
        <<"user_dn">> => list_to_binary(?ALICE_DN),
        <<"password">> => LargeValue
    },
    ?BAD_REQUEST = api_put(Config, ?ENDPOINT, Body).

invalid_json_rejected(Config) ->
    ?BAD_REQUEST = api_put_raw_body(Config, ?ENDPOINT, "not valid json {{{").

non_object_body_rejected(Config) ->
    ?BAD_REQUEST = api_put_raw_body(Config, ?ENDPOINT, "[1,2,3]").

%%--------------------------------------------------------------------
%% HTTP helpers
%%--------------------------------------------------------------------

api_put(Config, Path, Body) ->
    JsonBody = rabbit_json:encode(Body),
    Port = rabbit_ct_broker_helpers:get_node_config(Config, 0, tcp_port_mgmt),
    Url = lists:flatten(io_lib:format(
        "http://localhost:~b/api~s", [Port, Path])),
    Headers = [auth_header("guest", "guest"),
               {"content-type", "application/json"}],
    {ok, {{_, Status, _}, _, _}} =
        httpc:request(put, {Url, Headers, "application/json", JsonBody},
                      [{timeout, 30000}], []),
    Status.

api_put_with_body(Config, Path, Body) ->
    JsonBody = rabbit_json:encode(Body),
    Port = rabbit_ct_broker_helpers:get_node_config(Config, 0, tcp_port_mgmt),
    Url = lists:flatten(io_lib:format(
        "http://localhost:~b/api~s", [Port, Path])),
    Headers = [auth_header("guest", "guest"),
               {"content-type", "application/json"}],
    {ok, {{_, Status, _}, _, RespBody}} =
        httpc:request(put, {Url, Headers, "application/json", JsonBody},
                      [{timeout, 30000}], []),
    case RespBody of
        [] -> {Status, #{}};
        _ ->
            Decoded = rabbit_json:decode(list_to_binary(RespBody)),
            {Status, Decoded}
    end.

api_put_raw_body(Config, Path, RawBody) ->
    Port = rabbit_ct_broker_helpers:get_node_config(Config, 0, tcp_port_mgmt),
    Url = lists:flatten(io_lib:format(
        "http://localhost:~b/api~s", [Port, Path])),
    Headers = [auth_header("guest", "guest"),
               {"content-type", "application/json"}],
    {ok, {{_, Status, _}, _, _}} =
        httpc:request(put, {Url, Headers, "application/json", RawBody},
                      [{timeout, 30000}], []),
    Status.

api_put_no_auth(Config, Path, Body) ->
    JsonBody = rabbit_json:encode(Body),
    Port = rabbit_ct_broker_helpers:get_node_config(Config, 0, tcp_port_mgmt),
    Url = lists:flatten(io_lib:format(
        "http://localhost:~b/api~s", [Port, Path])),
    {ok, {{_, Status, _}, _, _}} =
        httpc:request(put, {Url, [], "application/json", JsonBody},
                      [{timeout, 30000}], []),
    Status.

api_get_status(Config, Path) ->
    Port = rabbit_ct_broker_helpers:get_node_config(Config, 0, tcp_port_mgmt),
    Url = lists:flatten(io_lib:format(
        "http://localhost:~b/api~s", [Port, Path])),
    Headers = [auth_header("guest", "guest")],
    {ok, {{_, Status, _}, _, _}} =
        httpc:request(get, {Url, Headers}, [{timeout, 30000}], []),
    Status.

api_post_status(Config, Path, Body) ->
    JsonBody = rabbit_json:encode(Body),
    Port = rabbit_ct_broker_helpers:get_node_config(Config, 0, tcp_port_mgmt),
    Url = lists:flatten(io_lib:format(
        "http://localhost:~b/api~s", [Port, Path])),
    Headers = [auth_header("guest", "guest"),
               {"content-type", "application/json"}],
    {ok, {{_, Status, _}, _, _}} =
        httpc:request(post, {Url, Headers, "application/json", JsonBody},
                      [{timeout, 30000}], []),
    Status.

api_delete_status(Config, Path) ->
    Port = rabbit_ct_broker_helpers:get_node_config(Config, 0, tcp_port_mgmt),
    Url = lists:flatten(io_lib:format(
        "http://localhost:~b/api~s", [Port, Path])),
    Headers = [auth_header("guest", "guest")],
    {ok, {{_, Status, _}, _, _}} =
        httpc:request(delete, {Url, Headers}, [{timeout, 30000}], []),
    Status.

auth_header(User, Pass) ->
    {"Authorization",
     "Basic " ++ binary_to_list(base64:encode(User ++ ":" ++ Pass))}.
