%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.

-module(auth_validation_semaphore_SUITE).
-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

all() ->
    [acquire_and_release,
     rejects_when_capacity_exhausted,
     slot_freed_on_holder_death,
     release_is_idempotent].

init_per_suite(Config) ->
    application:set_env(rabbitmq_auth_validation, max_concurrent, 2),
    {ok, Pid} = rabbit_auth_validation_semaphore:start_link(),
    [{semaphore_pid, Pid} | Config].

end_per_suite(Config) ->
    Pid = ?config(semaphore_pid, Config),
    unlink(Pid),
    exit(Pid, shutdown),
    ok.

init_per_testcase(_Testcase, Config) ->
    %% Drain any leftover tokens from previous tests by restarting
    Pid = ?config(semaphore_pid, Config),
    unlink(Pid),
    exit(Pid, shutdown),
    timer:sleep(50),
    {ok, NewPid} = rabbit_auth_validation_semaphore:start_link(),
    [{semaphore_pid, NewPid} | proplists:delete(semaphore_pid, Config)].

end_per_testcase(_Testcase, _Config) ->
    ok.

%%--------------------------------------------------------------------

acquire_and_release(_Config) ->
    {ok, T1} = rabbit_auth_validation_semaphore:acquire(),
    {ok, T2} = rabbit_auth_validation_semaphore:acquire(),
    ?assertEqual({error, capacity_exhausted},
                 rabbit_auth_validation_semaphore:acquire()),
    ok = rabbit_auth_validation_semaphore:release(T1),
    {ok, T3} = rabbit_auth_validation_semaphore:acquire(),
    ok = rabbit_auth_validation_semaphore:release(T2),
    ok = rabbit_auth_validation_semaphore:release(T3).

rejects_when_capacity_exhausted(_Config) ->
    {ok, T1} = rabbit_auth_validation_semaphore:acquire(),
    {ok, T2} = rabbit_auth_validation_semaphore:acquire(),
    ?assertEqual({error, capacity_exhausted},
                 rabbit_auth_validation_semaphore:acquire()),
    ?assertEqual({error, capacity_exhausted},
                 rabbit_auth_validation_semaphore:acquire()),
    ok = rabbit_auth_validation_semaphore:release(T1),
    ok = rabbit_auth_validation_semaphore:release(T2).

slot_freed_on_holder_death(_Config) ->
    %% Acquire from a spawned process that immediately dies
    Self = self(),
    Pid = spawn(fun() ->
        {ok, _Token} = rabbit_auth_validation_semaphore:acquire(),
        Self ! acquired,
        %% Die without releasing
        ok
    end),
    receive acquired -> ok after 5000 -> ct:fail(timeout) end,
    %% Wait for the DOWN message to be processed
    wait_for_process_death(Pid),
    timer:sleep(50),
    %% Both slots should be available now (one was freed by death)
    {ok, T1} = rabbit_auth_validation_semaphore:acquire(),
    {ok, T2} = rabbit_auth_validation_semaphore:acquire(),
    ok = rabbit_auth_validation_semaphore:release(T1),
    ok = rabbit_auth_validation_semaphore:release(T2).

release_is_idempotent(_Config) ->
    {ok, Token} = rabbit_auth_validation_semaphore:acquire(),
    ok = rabbit_auth_validation_semaphore:release(Token),
    %% Releasing again should not crash or corrupt state
    ok = rabbit_auth_validation_semaphore:release(Token),
    %% Both slots should still be available
    {ok, T1} = rabbit_auth_validation_semaphore:acquire(),
    {ok, T2} = rabbit_auth_validation_semaphore:acquire(),
    ok = rabbit_auth_validation_semaphore:release(T1),
    ok = rabbit_auth_validation_semaphore:release(T2).

%%--------------------------------------------------------------------

wait_for_process_death(Pid) ->
    Ref = monitor(process, Pid),
    receive
        {'DOWN', Ref, process, Pid, _} -> ok
    after 5000 ->
        ct:fail({process_still_alive, Pid})
    end.
