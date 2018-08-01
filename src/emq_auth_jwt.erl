%%--------------------------------------------------------------------
%% Copyright (c) 2013-2018 EMQ Enterprise, Inc. (http://emqtt.io)
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(emq_auth_jwt).

-include_lib("emqttd/include/emqttd.hrl").

-behaviour(emqttd_auth_mod).

%% emqttd_auth callbacks
-export([init/1, check/3, description/0]).

%%--------------------------------------------------------------------
%% emqttd_auth_mod Callbacks
%%--------------------------------------------------------------------

init(Env) ->
    {ok, Env}.

check(_Client, undefined, _Env) ->
    {error, token_undefined};
check(Client, Token, Env) ->
    case catch jwerl:header(Token) of
        {'EXIT', _} -> ignore; % Not a JWT Token
        Headers -> verify_token(Client, Headers, Token, Env)
    end.

verify_token(_Client, #{alg := <<"HS", _/binary>>}, _Token, #{secret := undefined}) ->
    {error, hmac_secret_undefined};
verify_token(Client, #{alg := Alg = <<"HS", _/binary>>}, Token, Env = #{secret := Secret}) ->
    verify_token(Client, Alg, Token, Secret, Env);
verify_token(_Client, #{alg := <<"RS", _/binary>>}, _Token, #{pubkey := undefined}) ->
    {error, rsa_pubkey_undefined};
verify_token(Client, #{alg := Alg = <<"RS", _/binary>>}, Token, Env = #{pubkey := PubKey}) ->
    verify_token(Client, Alg, Token, PubKey, Env);
verify_token(_Client, #{alg := <<"ES", _/binary>>}, _Token, #{pubkey := undefined}) ->
    {error, ecdsa_pubkey_undefined};
verify_token(Client, #{alg := Alg = <<"ES", _/binary>>}, Token, Env = #{pubkey := PubKey}) ->
    verify_token(Client, Alg, Token, PubKey, Env);
verify_token(_Client, Header, _Token, _Env) ->
    lager:error("Unsupported token: ~p", [Header]),
    {error, token_unsupported}.

verify_token(Client, Alg, Token, SecretOrKey, Env) ->
    case catch jwerl:verify(Token, decode_algo(Alg), SecretOrKey) of
        {ok, Claims}  ->
            setup_acl(Client, maps:get(scopes, Claims, []), Env),
            ok;
        {error, Reason} ->
            lager:error("JWT decode error:~p", [Reason]),
            {error, token_error};
        {'EXIT', Error} ->
            lager:error("JWT decode error:~p", [Error]),
            {error, token_error}
    end.

setup_acl(_Client, _Scopes, #{scopes := false}) ->
    ok;
setup_acl(Client, Scopes, _Env) ->
    emq_acl_jwt:set_scopes(Client, Scopes),
    ok.

decode_algo(<<"HS256">>) -> hs256;
decode_algo(<<"HS384">>) -> hs384;
decode_algo(<<"HS512">>) -> hs512;
decode_algo(<<"RS256">>) -> rs256;
decode_algo(<<"RS384">>) -> rs384;
decode_algo(<<"RS512">>) -> rs512;
decode_algo(<<"ES256">>) -> es256;
decode_algo(<<"ES384">>) -> es384;
decode_algo(<<"ES512">>) -> es512;
decode_algo(<<"none">>)  -> none;
decode_algo(Alg) -> throw({error, {unsupported_algorithm, Alg}}).

description() ->
    "Authentication with JWT".
