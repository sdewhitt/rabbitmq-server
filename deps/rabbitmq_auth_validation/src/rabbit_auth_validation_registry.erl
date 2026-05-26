%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Resolves a method path segment (e.g. <<"ldap-simple-bind">>) to the
%% backend module that handles it. A method is only routable if it is
%% both a registered backend AND included in the application's
%% enabled_methods environment variable. Either condition failing yields
%% a 404 from the dispatcher.

-module(rabbit_auth_validation_registry).

-export([find_backend/1, allowed_fields_for/1]).

%% Built-in backends. New methods register themselves here. The list is
%% intentionally small and explicit rather than discovered dynamically:
%% an operator restricting enabled_methods should be able to reason
%% about the full set of routable backends from configuration alone.
-define(BACKENDS, [rabbit_auth_validation_ldap]).

-spec find_backend(binary()) -> {ok, module()} | {error, not_found}.
find_backend(MethodName) when is_binary(MethodName) ->
    case enabled(MethodName) of
        false ->
            {error, not_found};
        true ->
            find_in_modules(MethodName, ?BACKENDS)
    end.

-spec allowed_fields_for(module()) -> [binary()].
allowed_fields_for(Module) ->
    Defaults = Module:allowed_fields(),
    case application:get_env(rabbitmq_auth_validation, allowed_fields_overrides) of
        undefined ->
            Defaults;
        {ok, Overrides} ->
            MethodName = Module:method_name(),
            case lists:keyfind(MethodName, 1, Overrides) of
                {MethodName, Fields} when is_list(Fields) ->
                    %% Intersection: an override can only narrow, never widen,
                    %% the backend's declared field set. This protects against
                    %% misconfiguration accidentally enabling unsupported fields.
                    [F || F <- Fields, lists:member(F, Defaults)];
                _ ->
                    Defaults
            end
    end.

%%--------------------------------------------------------------------

enabled(MethodName) ->
    {ok, Enabled} = application:get_env(rabbitmq_auth_validation, enabled_methods),
    lists:member(MethodName, Enabled).

find_in_modules(_MethodName, []) ->
    {error, not_found};
find_in_modules(MethodName, [Module | Rest]) ->
    case Module:method_name() of
        MethodName -> {ok, Module};
        _          -> find_in_modules(MethodName, Rest)
    end.
