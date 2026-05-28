%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Cowboy REST handler for the auth validation endpoint.
%%
%% Mounted at PUT /api/auth/validate/:method by the rabbit_mgmt_extension
%% behaviour. The handler enforces, in order:
%%
%%   1. Management API authentication (via rabbit_mgmt_util:is_authorized/2)
%%   2. Required user tag (default: administrator)
%%   3. Body size cap (rejects oversized requests before parsing)
%%   4. Per-source-IP rate limit (blunts brute-forcing)
%%   5. Concurrency semaphore (caps outbound connections)
%%   6. Method routing (404 for unknown / disabled methods)
%%   7. Field allowlist (strips fields the operator has not permitted)
%%
%% Only after every gate passes does the request reach the backend.

-module(rabbit_auth_validation_handler).

-behaviour(rabbit_mgmt_extension).

-export([dispatcher/0, web_ui/0]).
-export([init/2,
         allowed_methods/2,
         content_types_accepted/2,
         resource_exists/2,
         is_authorized/2,
         accept_content/2]).

-include_lib("kernel/include/logger.hrl").
-include_lib("rabbit_common/include/rabbit.hrl").
-include_lib("rabbitmq_management_agent/include/rabbit_mgmt_records.hrl").

dispatcher() ->
    [{"/auth/validate/:method", ?MODULE, []}].

web_ui() -> [].

%%--------------------------------------------------------------------
%% Cowboy REST callbacks
%%--------------------------------------------------------------------

init(Req, _Opts) ->
    {cowboy_rest, rabbit_mgmt_cors:set_headers(Req, ?MODULE), #context{}}.

allowed_methods(Req, Context) ->
    {[<<"PUT">>, <<"OPTIONS">>], Req, Context}.

content_types_accepted(Req, Context) ->
    {[{'*', accept_content}], Req, Context}.

resource_exists(Req, Context) ->
    %% Always true; method routing happens in accept_content/2 so we
    %% can return a 404 with a structured body.
    {true, Req, Context}.

is_authorized(Req, Context) ->
    case rabbit_mgmt_util:is_authorized(Req, Context) of
        {true, Req1, Ctx1} ->
            check_user_tag(Req1, Ctx1);
        Other ->
            Other
    end.

accept_content(Req0, Context) ->
    Method = cowboy_req:binding(method, Req0),
    case rabbit_auth_validation_registry:find_backend(Method) of
        {error, not_found} ->
            reply(404, not_found,
                  <<"unknown or disabled validation method">>, Req0, Context);
        {ok, Backend} ->
            with_gates(Backend, Req0, Context)
    end.

%%--------------------------------------------------------------------
%% Pipeline
%%--------------------------------------------------------------------

with_gates(Backend, Req0, Context) ->
    Source = source_ip(Req0),
    case rabbit_auth_validation_rate_limiter:check(Source) of
        {error, rate_limited} ->
            audit(Backend, Source, rate_limited, 0),
            Req1 = cowboy_req:set_resp_header(<<"retry-after">>, <<"60">>, Req0),
            reply(429, rate_limited,
                  <<"too many validation requests">>, Req1, Context);
        ok ->
            with_semaphore(Backend, Source, Req0, Context)
    end.

with_semaphore(Backend, Source, Req0, Context) ->
    case rabbit_auth_validation_semaphore:acquire() of
        {error, capacity_exhausted} ->
            audit(Backend, Source, capacity_exhausted, 0),
            Req1 = cowboy_req:set_resp_header(<<"retry-after">>, <<"5">>, Req0),
            reply(503, capacity_exhausted,
                  <<"validation capacity exhausted">>, Req1, Context);
        {ok, Token} ->
            try
                with_body(Backend, Source, Req0, Context)
            after
                rabbit_auth_validation_semaphore:release(Token)
            end
    end.

with_body(Backend, Source, Req0, Context) ->
    MaxBytes = application:get_env(rabbitmq_auth_validation, max_body_size, 65536),
    case rabbit_mgmt_util:read_complete_body_with_limit(Req0, MaxBytes) of
        {error, http_body_limit_exceeded, _Limit, _Read} ->
            audit(Backend, Source, body_too_large, 0),
            reply(400, body_too_large,
                  <<"request body exceeds configured limit">>, Req0, Context);
        {ok, Body, Req1} ->
            with_decoded(Backend, Source, Body, Req1, Context)
    end.

with_decoded(Backend, Source, Body, Req, Context) ->
    case decode_json(Body) of
        {error, _Reason} ->
            audit(Backend, Source, invalid_json, 0),
            reply(400, input_invalid, <<"invalid JSON">>, Req, Context);
        {ok, Map} when is_map(Map) ->
            Filtered = filter_fields(Backend, Map),
            dispatch(Backend, Source, Filtered, Req, Context);
        {ok, _Other} ->
            reply(400, input_invalid,
                  <<"request body must be a JSON object">>, Req, Context)
    end.

dispatch(Backend, Source, Body, Req, Context) ->
    Start = erlang:monotonic_time(millisecond),
    Result = safe_validate(Backend, Body),
    Duration = erlang:monotonic_time(millisecond) - Start,
    case Result of
        ok ->
            audit(Backend, Source, ok, Duration),
            Req1 = cowboy_req:reply(204, #{}, <<>>, Req),
            {stop, Req1, Context};
        {error, Category, Reason} ->
            audit(Backend, Source, Category, Duration),
            Status = status_for_category(Category),
            reply(Status, Category, Reason, Req, Context)
    end.

safe_validate(Backend, Body) ->
    try Backend:validate(Body)
    catch
        Class:Err:Stack ->
            ?LOG_WARNING("auth_validation backend ~p crashed: ~p:~p~n~p",
                         [Backend, Class, Err, Stack]),
            {error, input_invalid, <<"validation crashed; see broker logs">>}
    end.

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

check_user_tag(Req, #context{user = #user{tags = Tags}} = Ctx) ->
    Required = application:get_env(rabbitmq_auth_validation,
                                   required_user_tag, administrator),
    case lists:member(Required, Tags) of
        true ->
            {true, Req, Ctx};
        false ->
            {{false, <<"Basic realm=\"RabbitMQ Management\"">>}, Req, Ctx}
    end;
check_user_tag(Req, Ctx) ->
    {{false, <<"Basic realm=\"RabbitMQ Management\"">>}, Req, Ctx}.

filter_fields(Backend, Map) ->
    Allowed = rabbit_auth_validation_registry:allowed_fields_for(Backend),
    maps:with(Allowed, Map).

decode_json(Body) ->
    try {ok, rabbit_json:decode(Body)}
    catch _:_ -> {error, invalid_json}
    end.

status_for_category(input_invalid)     -> 400;
status_for_category(connection_failed) -> 400;
status_for_category(tls_failed)        -> 400;
status_for_category(auth_failed)       -> 422;
status_for_category(config_conflict)   -> 422.

reply(Status, Category, Reason, Req, Context) ->
    Body = rabbit_json:encode(#{<<"error">> => atom_to_binary(Category, utf8),
                                <<"reason">> => Reason}),
    Headers = #{<<"content-type">> => <<"application/json">>},
    Req1 = cowboy_req:reply(Status, Headers, Body, Req),
    {stop, Req1, Context}.

source_ip(Req) ->
    case cowboy_req:peer(Req) of
        {Addr, _Port} -> Addr;
        _             -> unknown
    end.

audit(Backend, Source, Result, DurationMs) ->
    Method = try Backend:method_name() catch _:_ -> <<"unknown">> end,
    ?LOG_INFO("auth_validation: method=~s source=~s result=~p duration_ms=~B",
              [Method, format_source(Source), Result, DurationMs],
              #{domain => [rabbitmq, auth_validation]}).

format_source({_, _, _, _} = IPv4) ->
    list_to_binary(inet:ntoa(IPv4));
format_source({_, _, _, _, _, _, _, _} = IPv6) ->
    list_to_binary(inet:ntoa(IPv6));
format_source(Other) ->
    iolist_to_binary(io_lib:format("~p", [Other])).
