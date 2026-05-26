%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Counting semaphore that bounds the number of concurrent outbound
%% validation connections. The semaphore exists in the request path
%% before any outbound network call so that an attacker cannot exhaust
%% broker resources by flooding validation requests.
%%
%% acquire/0 returns immediately: either {ok, Token} on success or
%% {error, capacity_exhausted} when the limit is reached. Callers MUST
%% release/1 the token in an after-block so a crashing handler does not
%% leak slots.

-module(rabbit_auth_validation_semaphore).

-behaviour(gen_server).

-export([start_link/0, acquire/0, release/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-record(state, {capacity :: non_neg_integer(),
                in_use   :: non_neg_integer(),
                holders  :: #{reference() => pid()}}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec acquire() -> {ok, reference()} | {error, capacity_exhausted}.
acquire() ->
    gen_server:call(?MODULE, {acquire, self()}).

-spec release(reference()) -> ok.
release(Token) when is_reference(Token) ->
    gen_server:cast(?MODULE, {release, Token}).

%%--------------------------------------------------------------------

init([]) ->
    Capacity = application:get_env(rabbitmq_auth_validation, max_concurrent, 5),
    {ok, #state{capacity = Capacity, in_use = 0, holders = #{}}}.

handle_call({acquire, _Pid}, _From, #state{capacity = Cap, in_use = N} = State)
        when N >= Cap ->
    {reply, {error, capacity_exhausted}, State};
handle_call({acquire, Pid}, _From, #state{in_use = N, holders = H} = State) ->
    %% Monitor the holder so a crashing handler frees its slot.
    Ref = erlang:monitor(process, Pid),
    {reply, {ok, Ref}, State#state{in_use = N + 1, holders = H#{Ref => Pid}}}.

handle_cast({release, Ref}, State) ->
    {noreply, drop_holder(Ref, State)}.

handle_info({'DOWN', Ref, process, _Pid, _Reason}, State) ->
    {noreply, drop_holder(Ref, State)};
handle_info(_Other, State) ->
    {noreply, State}.

drop_holder(Ref, #state{in_use = N, holders = H} = State) ->
    case maps:take(Ref, H) of
        {_Pid, H1} ->
            erlang:demonitor(Ref, [flush]),
            State#state{in_use = max(0, N - 1), holders = H1};
        error ->
            State
    end.
