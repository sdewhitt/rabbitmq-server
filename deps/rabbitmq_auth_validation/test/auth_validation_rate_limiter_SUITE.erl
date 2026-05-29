%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.

-module(auth_validation_rate_limiter_SUITE).
-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

all() ->
    [rejects_after_max_requests,
     per_ip_isolation,
     window_reset_allows_new_requests,
     reset_clears_all_buckets].

init_per_suite(Config) ->
    application:set_env(rabbitmq_auth_validation, rate_limit_window_ms, 60000),
    application:set_env(rabbitmq_auth_validation, rate_limit_max_requests, 3),
    {ok, Pid} = rabbit_auth_validation_rate_limiter:start_link(),
    [{rate_limiter_pid, Pid} | Config].

end_per_suite(Config) ->
    Pid = ?config(rate_limiter_pid, Config),
    unlink(Pid),
    exit(Pid, shutdown),
    ok.

init_per_testcase(_Testcase, Config) ->
    rabbit_auth_validation_rate_limiter:reset(),
    Config.

end_per_testcase(_Testcase, _Config) ->
    ok.

%%--------------------------------------------------------------------

rejects_after_max_requests(_Config) ->
    Source = {127, 0, 0, 1},
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source)),
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source)),
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source)),
    ?assertEqual({error, rate_limited},
                 rabbit_auth_validation_rate_limiter:check(Source)).

per_ip_isolation(_Config) ->
    Source1 = {10, 0, 0, 1},
    Source2 = {10, 0, 0, 2},
    %% Exhaust Source1
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source1)),
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source1)),
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source1)),
    ?assertEqual({error, rate_limited},
                 rabbit_auth_validation_rate_limiter:check(Source1)),
    %% Source2 should still be allowed
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source2)),
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source2)),
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source2)),
    ?assertEqual({error, rate_limited},
                 rabbit_auth_validation_rate_limiter:check(Source2)).

window_reset_allows_new_requests(Config) ->
    %% Restart the rate limiter with a very short window
    Pid = ?config(rate_limiter_pid, Config),
    unlink(Pid),
    exit(Pid, shutdown),
    timer:sleep(50),
    application:set_env(rabbitmq_auth_validation, rate_limit_window_ms, 50),
    {ok, NewPid} = rabbit_auth_validation_rate_limiter:start_link(),

    Source = {172, 16, 0, 1},
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source)),
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source)),
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source)),
    ?assertEqual({error, rate_limited},
                 rabbit_auth_validation_rate_limiter:check(Source)),
    %% Wait for window to expire
    timer:sleep(100),
    %% Should be allowed again
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source)),

    %% Restore original config for subsequent tests
    unlink(NewPid),
    exit(NewPid, shutdown),
    timer:sleep(50),
    application:set_env(rabbitmq_auth_validation, rate_limit_window_ms, 60000),
    {ok, _} = rabbit_auth_validation_rate_limiter:start_link().

reset_clears_all_buckets(_Config) ->
    Source = {192, 168, 1, 1},
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source)),
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source)),
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source)),
    ?assertEqual({error, rate_limited},
                 rabbit_auth_validation_rate_limiter:check(Source)),
    rabbit_auth_validation_rate_limiter:reset(),
    ?assertEqual(ok, rabbit_auth_validation_rate_limiter:check(Source)).
