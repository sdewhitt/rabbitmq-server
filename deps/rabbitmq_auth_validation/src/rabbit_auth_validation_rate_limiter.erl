%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Per-source-IP fixed-window rate limiter. The window resets after
%% rate_limit_window_ms; within a window, a source may issue at most
%% rate_limit_max_requests successful check/1 calls. The intent is to
%% blunt credential brute-forcing, not to provide precise traffic
%% shaping. We deliberately keep the implementation simple to avoid
%% becoming an attack surface in its own right.

-module(rabbit_auth_validation_rate_limiter).

-behaviour(gen_server).

-export([start_link/0, check/1, reset/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-record(state, {window_ms       :: pos_integer(),
                max_per_window  :: pos_integer(),
                buckets         :: #{Source :: term() => {Count :: non_neg_integer(),
                                                          WindowStart :: integer()}}}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec check(Source :: term()) -> ok | {error, rate_limited}.
check(Source) ->
    gen_server:call(?MODULE, {check, Source}).

-spec reset() -> ok.
reset() ->
    gen_server:cast(?MODULE, reset).

%%--------------------------------------------------------------------

init([]) ->
    Window = application:get_env(rabbitmq_auth_validation, rate_limit_window_ms, 60000),
    Max    = application:get_env(rabbitmq_auth_validation, rate_limit_max_requests, 10),
    {ok, #state{window_ms = Window, max_per_window = Max, buckets = #{}}}.

handle_call({check, Source}, _From, #state{window_ms = W,
                                           max_per_window = Max,
                                           buckets = B} = State) ->
    Now = erlang:monotonic_time(millisecond),
    {Count, WindowStart} = maps:get(Source, B, {0, Now}),
    {NewCount, NewStart} =
        case Now - WindowStart >= W of
            true  -> {1, Now};
            false -> {Count + 1, WindowStart}
        end,
    case NewCount > Max of
        true ->
            %% Reject without updating the bucket count beyond the limit so
            %% that floods do not extend the rejection window arbitrarily.
            {reply, {error, rate_limited}, State#state{buckets = B#{Source => {Max + 1, NewStart}}}};
        false ->
            {reply, ok, State#state{buckets = B#{Source => {NewCount, NewStart}}}}
    end.

handle_cast(reset, State) ->
    {noreply, State#state{buckets = #{}}}.

handle_info(_Msg, State) ->
    {noreply, State}.
