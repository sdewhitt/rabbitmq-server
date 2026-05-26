%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Behaviour implemented by every validation method backend.
%%
%% Each backend is responsible for performing the validation against
%% an external system (LDAP server, OAuth issuer, HTTP endpoint, ...)
%% and returning a categorised result. Backends MUST NOT touch any
%% HTTP request or response objects: the dispatcher maps result tuples
%% to HTTP responses uniformly.

-module(rabbit_auth_validation_backend).

-type error_category() ::
    input_invalid       %% Malformed / missing / wrong-typed input
  | connection_failed   %% Could not reach the target server
  | tls_failed          %% TLS handshake or certificate validation failed
  | auth_failed         %% Server reachable but credentials rejected
  | config_conflict.    %% Contradictory settings (e.g. ssl + starttls)

-type result() ::
    ok
  | {error, error_category(), Reason :: binary()}.

-export_type([error_category/0, result/0]).

%% The path segment this backend handles, e.g. <<"ldap-simple-bind">>.
-callback method_name() -> binary().

%% Validate a request body. Returns ok on success or a categorised error.
%% Implementations MUST NOT raise; unexpected errors MUST be caught and
%% mapped to {error, Category, Reason}.
-callback validate(Body :: map()) -> result().

%% The full set of fields this backend accepts. Used by the dispatcher to
%% strip unknown fields before invoking validate/1, so an operator who
%% restricts fields via configuration cannot accidentally widen the API.
-callback allowed_fields() -> [binary()].
