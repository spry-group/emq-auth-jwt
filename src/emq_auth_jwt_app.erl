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

-module(emq_auth_jwt_app).

-behaviour(application).

-import(application, [get_env/2, get_env/3]).

-export([start/2, stop/1]).

-behaviour(supervisor).

-export([init/1]).

-define(APP, emq_auth_jwt).

start(_Type, _Args) ->
    {ok, Pid} = supervisor:start_link({local, ?MODULE}, ?MODULE, []),
    Auth_Env = auth_env(),
    ACL_Env = acl_env(),
    emqttd_access_control:register_mod(auth, emq_auth_jwt, Auth_Env),
    emqttd_access_control:register_mod(acl, emq_acl_jwt, ACL_Env),
    emq_auth_jwt_config:register(),
    emqttd:hook('client.disconnected',
                fun emq_acl_jwt:on_client_disconnected/3,
                [ACL_Env]),
    {ok, Pid}.

stop(_State) ->
    emqttd_access_control:unregister_mod(auth, emq_auth_jwt),
    emqttd_access_control:unregister_mod(auth, emq_acl_jwt),
    emq_auth_jwt_config:unregister(),
    emqttd:unhook('client.disconnected',
                  fun emq_acl_jwt:on_client_disconnected/3).

%%--------------------------------------------------------------------
%% Dummy Supervisor
%%--------------------------------------------------------------------

init([]) ->
    {ok, { {one_for_all, 1, 10}, []} }.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

auth_env() ->
    #{secret => get_env(?APP, secret, undefined),
      pubkey => read_pubkey(),
      scopes => get_env(?APP, scopes, false)}.

acl_env() ->
    #{scopes => get_env(?APP, scopes, false)}.

read_pubkey() ->
    case get_env(?APP, pubkey) of
        undefined  -> undefined;
        {ok, Path} -> {ok, PubKey} = file:read_file(Path),
                      PubKey
    end.

