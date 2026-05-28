%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% LDAP simple-bind validation backend.
%%
%% Implements the rabbit_auth_validation_backend behaviour. The flow is:
%%
%%   1. Type-check the input map (raises {input_invalid, Reason} on
%%      failure; never propagates raw eldap errors to the caller).
%%   2. eldap:open/2 the configured server list with a bounded timeout.
%%   3. Optionally upgrade with eldap:start_tls/3.
%%   4. eldap:simple_bind/3 with the supplied credentials.
%%   5. eldap:close/1 unconditionally in an after-block.
%%
%% Connection lifetime is bounded by the request: nothing is pooled,
%% nothing is cached. The validation is indistinguishable from a no-op
%% to the rest of the broker.
%%
%% This module is derived from PR #14414's rabbit_auth_backend_ldap_mgmt
%% but returns categorised tuples instead of HTTP responses, so the
%% dispatcher can apply uniform error mapping across backends.

-module(rabbit_auth_validation_ldap).

-behaviour(rabbit_auth_validation_backend).

-export([method_name/0, validate/1, allowed_fields/0]).

-include_lib("kernel/include/logger.hrl").

-define(DEFAULT_PORT, 389).
-define(METHOD, <<"ldap-simple-bind">>).

method_name() -> ?METHOD.

allowed_fields() ->
    [<<"servers">>, <<"port">>, <<"user_dn">>, <<"password">>,
     <<"use_ssl">>, <<"use_starttls">>, <<"ssl_options">>].

-spec validate(map()) -> rabbit_auth_validation_backend:result().
validate(Body) ->
    try
        Parsed = parse(Body),
        do_validate(Parsed)
    catch
        throw:{input_invalid, Reason} ->
            {error, input_invalid, to_binary(Reason)};
        throw:{config_conflict, Reason} ->
            {error, config_conflict, to_binary(Reason)};
        Class:Err:Stack ->
            ?LOG_WARNING("auth_validation_ldap unexpected error: ~p:~p~n~p",
                         [Class, Err, Stack]),
            {error, input_invalid, <<"unexpected validation error">>}
    end.

%%--------------------------------------------------------------------
%% Input parsing
%%--------------------------------------------------------------------

parse(Body) when is_map(Body) ->
    Servers     = require_servers(maps:get(<<"servers">>, Body, undefined)),
    Port        = parse_port(maps:get(<<"port">>, Body, ?DEFAULT_PORT)),
    UseSsl      = parse_bool(<<"use_ssl">>, maps:get(<<"use_ssl">>, Body, false)),
    UseStartTls = parse_bool(<<"use_starttls">>, maps:get(<<"use_starttls">>, Body, false)),
    UserDN      = require_user_dn(maps:get(<<"user_dn">>, Body, undefined)),
    Password    = require_password(maps:get(<<"password">>, Body, undefined)),
    SslOptsMap  = maps:get(<<"ssl_options">>, Body, undefined),

    case {UseSsl, UseStartTls} of
        {true, true} ->
            throw({config_conflict,
                   "use_ssl and use_starttls cannot both be true"});
        _ -> ok
    end,

    TlsOpts = parse_ssl_options(SslOptsMap),
    #{servers => Servers,
      port => Port,
      use_ssl => UseSsl,
      use_starttls => UseStartTls,
      user_dn => UserDN,
      password => Password,
      tls_opts => TlsOpts};
parse(_) ->
    throw({input_invalid, "request body must be a JSON object"}).

require_servers(undefined) ->
    throw({input_invalid, "servers is required"});
require_servers([]) ->
    throw({input_invalid, "servers must be a non-empty list"});
require_servers(L) when is_list(L) ->
    [bin_to_charlist(<<"servers">>, S) || S <- L];
require_servers(_) ->
    throw({input_invalid, "servers must be a list of strings"}).

require_user_dn(undefined) ->
    throw({input_invalid, "user_dn is required"});
require_user_dn(<<>>) ->
    %% Empty DN attempts an anonymous bind, which is not a meaningful
    %% validation and would produce a misleading "success" result.
    throw({input_invalid, "user_dn must not be empty"});
require_user_dn(B) when is_binary(B) ->
    B;
require_user_dn(_) ->
    throw({input_invalid, "user_dn must be a string"}).

require_password(undefined) ->
    throw({input_invalid, "password is required"});
require_password(<<>>) ->
    throw({input_invalid, "password must not be empty"});
require_password(B) when is_binary(B) ->
    B;
require_password(_) ->
    throw({input_invalid, "password must be a string"}).

parse_port(P) when is_integer(P), P > 0, P =< 65535 -> P;
parse_port(B) when is_binary(B) ->
    try binary_to_integer(B) of
        I when I > 0, I =< 65535 -> I;
        _ -> throw({input_invalid, "port must be in 1..65535"})
    catch
        error:badarg -> throw({input_invalid, "port must be an integer"})
    end;
parse_port(_) ->
    throw({input_invalid, "port must be an integer in 1..65535"}).

parse_bool(_Field, true)  -> true;
parse_bool(_Field, false) -> false;
parse_bool(Field, _) ->
    throw({input_invalid, io_lib:format("~s must be a boolean", [Field])}).

bin_to_charlist(_Field, B) when is_binary(B) -> binary_to_list(B);
bin_to_charlist(_Field, S) when is_list(S)   -> S;
bin_to_charlist(Field, _) ->
    throw({input_invalid, io_lib:format("~s entries must be strings", [Field])}).

%%--------------------------------------------------------------------
%% TLS option parsing (derived from PR #14414's tls_options/1)
%%--------------------------------------------------------------------

parse_ssl_options(undefined) ->
    [];
parse_ssl_options(M) when is_map(M) ->
    Opts0 = ca_opts(M),
    Opts1 = verify_opt(M, Opts0),
    Opts2 = depth_opt(M, Opts1),
    Opts3 = versions_opt(M, Opts2),
    Opts4 = sni_opt(M, Opts3),
    hostname_verification_opt(M, Opts4);
parse_ssl_options(_) ->
    throw({input_invalid, "ssl_options must be an object"}).

ca_opts(M) ->
    CaFile = maps:get(<<"cacertfile">>, M, undefined),
    CaPems = maps:get(<<"cacert_pem_data">>, M, undefined),
    Base = case {CaFile, CaPems} of
        {undefined, undefined} -> [{cacerts, public_key:cacerts_get()}];
        _ -> []
    end,
    Base1 = case CaFile of
        undefined -> Base;
        F when is_binary(F) -> [{cacertfile, binary_to_list(F)} | Base];
        F when is_list(F)   -> [{cacertfile, F} | Base];
        _ -> throw({input_invalid, "ssl_options.cacertfile must be a string"})
    end,
    case CaPems of
        undefined -> Base1;
        Pems when is_list(Pems) ->
            DerEncoded = lists:flatmap(fun decode_pem/1, Pems),
            [{cacerts, DerEncoded} | Base1];
        _ -> throw({input_invalid, "ssl_options.cacert_pem_data must be a list of PEM strings"})
    end.

decode_pem(P) when is_binary(P) ->
    try public_key:pem_decode(P) of
        [] ->
            throw({input_invalid, "ssl_options.cacert_pem_data: no certificates found"});
        Entries ->
            [Der || {'Certificate', Der, not_encrypted} <- Entries]
    catch
        error:_ -> throw({input_invalid, "ssl_options.cacert_pem_data: invalid PEM"})
    end;
decode_pem(_) ->
    throw({input_invalid, "ssl_options.cacert_pem_data entries must be strings"}).

verify_opt(M, Opts) ->
    case maps:get(<<"verify">>, M, undefined) of
        undefined -> Opts;
        <<"verify_peer">> -> [{verify, verify_peer} | Opts];
        <<"verify_none">> -> [{verify, verify_none} | Opts];
        _ -> throw({input_invalid, "ssl_options.verify must be verify_peer or verify_none"})
    end.

depth_opt(M, Opts) ->
    case maps:get(<<"depth">>, M, undefined) of
        undefined -> Opts;
        D when is_integer(D), D >= 0, D =< 255 -> [{depth, D} | Opts];
        _ -> throw({input_invalid, "ssl_options.depth must be an integer in 0..255"})
    end.

versions_opt(M, Opts) ->
    case maps:get(<<"versions">>, M, undefined) of
        undefined -> Opts;
        Vs when is_list(Vs) ->
            Atoms = [parse_version(V) || V <- Vs],
            [{versions, Atoms} | Opts];
        _ -> throw({input_invalid, "ssl_options.versions must be a list of strings"})
    end.

parse_version(V) when is_binary(V) ->
    try binary_to_existing_atom(V, utf8)
    catch error:badarg ->
        throw({input_invalid, <<"ssl_options.versions: unknown TLS version: ", V/binary>>})
    end;
parse_version(_) ->
    throw({input_invalid, "ssl_options.versions entries must be strings"}).

sni_opt(M, Opts) ->
    case maps:get(<<"server_name_indication">>, M, undefined) of
        undefined -> Opts;
        S when is_binary(S) -> [{server_name_indication, binary_to_list(S)} | Opts];
        _ -> throw({input_invalid, "ssl_options.server_name_indication must be a string"})
    end.

hostname_verification_opt(M, Opts) ->
    case maps:get(<<"ssl_hostname_verification">>, M, undefined) of
        undefined ->
            Opts;
        <<"wildcard">> ->
            MatchFun = public_key:pkix_verify_hostname_match_fun(https),
            [{customize_hostname_check, [{match_fun, MatchFun}]} | Opts];
        _ ->
            throw({input_invalid, "ssl_options.ssl_hostname_verification must be \"wildcard\""})
    end.

%%--------------------------------------------------------------------
%% Validation
%%--------------------------------------------------------------------

do_validate(#{servers := Servers, port := Port,
              use_ssl := UseSsl, use_starttls := UseStartTls,
              user_dn := UserDN, password := Password,
              tls_opts := TlsOpts}) ->
    Timeout = application:get_env(rabbitmq_auth_validation, connection_timeout_ms, 5000),
    OpenOpts0 = [{port, Port}, {timeout, Timeout}],
    OpenOpts1 = case UseSsl of
        true  -> [{ssl, true}, {sslopts, TlsOpts} | OpenOpts0];
        false -> OpenOpts0
    end,
    case eldap:open(Servers, OpenOpts1) of
        {ok, Conn} ->
            try
                bind(Conn, UseStartTls, TlsOpts, UserDN, Password, Timeout)
            after
                catch eldap:close(Conn)
            end;
        {error, Reason} ->
            ?LOG_DEBUG("auth_validation_ldap connection failed: ~p", [Reason]),
            {error, connection_failed, <<"could not connect to LDAP server">>}
    end.

bind(Conn, true = _UseStartTls, TlsOpts, UserDN, Password, Timeout) ->
    case eldap:start_tls(Conn, TlsOpts, Timeout) of
        ok ->
            simple_bind(Conn, UserDN, Password);
        {error, tls_already_started} ->
            {error, config_conflict,
             <<"cannot StartTLS on an already-TLS connection">>};
        {error, Reason} ->
            ?LOG_DEBUG("auth_validation_ldap StartTLS failed: ~p", [Reason]),
            {error, tls_failed, <<"StartTLS handshake failed">>}
    end;
bind(Conn, false, _TlsOpts, UserDN, Password, _Timeout) ->
    simple_bind(Conn, UserDN, Password).

simple_bind(Conn, UserDN, Password) ->
    case eldap:simple_bind(Conn, binary_to_list(UserDN), binary_to_list(Password)) of
        ok ->
            ok;
        {error, invalidCredentials} ->
            {error, auth_failed, <<"authentication failure">>};
        {error, unwillingToPerform} ->
            {error, auth_failed, <<"authentication failure">>};
        {error, invalidDNSyntax} ->
            {error, input_invalid, <<"DN syntax invalid or too long">>};
        {error, Reason} ->
            ?LOG_DEBUG("auth_validation_ldap bind failed: ~p", [Reason]),
            {error, auth_failed, <<"authentication failure">>}
    end.

%%--------------------------------------------------------------------

to_binary(B) when is_binary(B) -> B;
to_binary(L) when is_list(L)   -> iolist_to_binary(L);
to_binary(A) when is_atom(A)   -> atom_to_binary(A, utf8);
to_binary(Other)               -> iolist_to_binary(io_lib:format("~p", [Other])).
