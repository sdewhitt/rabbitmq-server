%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Supervises the rate limiter and concurrency semaphore that gate
%% incoming validation requests before they reach a backend.

-module(rabbit_auth_validation_sup).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    RateLimiter = #{
        id => rabbit_auth_validation_rate_limiter,
        start => {rabbit_auth_validation_rate_limiter, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [rabbit_auth_validation_rate_limiter]
    },
    Semaphore = #{
        id => rabbit_auth_validation_semaphore,
        start => {rabbit_auth_validation_semaphore, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [rabbit_auth_validation_semaphore]
    },
    SupFlags = #{strategy => one_for_one, intensity => 10, period => 10},
    {ok, {SupFlags, [RateLimiter, Semaphore]}}.
