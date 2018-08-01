-module(emq_acl_jwt).

-behaviour(emqttd_acl_mod).

-include_lib("emqttd/include/emqttd.hrl").

%% ACL Callbacks
-export([init/1, check_acl/2, reload_acl/1, description/0]).

%% Hooks
-export([on_client_disconnected/3]).

%% Private API
-export([set_scopes/2]).

-define(TAB, acl_jwt_rules).

init(Env = #{scopes := true}) ->
    ets:new(?TAB, [bag,
                   public,
                   named_table,
                   {read_concurrency, true},
                   {keypos, 2}]),
    {ok, Env};
init(Env) ->
    {ok, Env}.

check_acl({Client = #mqtt_client{client_id = ClientId}, PubSub, Topic},
          #{scopes := true}) ->
    case lookup(ClientId, PubSub) of
        {ok, Rules} ->
            case match(Client, Topic, Rules) of
                {matched, allow} -> allow;
                {matched, deny}  -> deny;
                nomatch          -> deny
            end;
        {error, not_found} ->
            ignore
    end;
check_acl(_, _Env) ->
    ignore.

reload_acl(_Env) ->
    ok.

description() ->
    "ACL with JWT".

on_client_disconnected(_Reason,
                       _Client = #mqtt_client{client_id = ClientId},
                       #{scopes := true}) ->
    ets:delete(?TAB, {client, ClientId}),
    ok;
on_client_disconnected(_Reason, _Client, _Env) ->
    ok.

lookup(ClientId, PubSub) ->
    case ets:lookup(?TAB, {client, ClientId}) of
        [] ->
            {error, not_found};
        Rules ->
            {ok, lists:filter(fun
                                  ({_, _, PS, _}) -> PS == PubSub;
                                  (_) -> false
                              end, Rules)}
    end.

match(_Client, _Topic, []) ->
    nomatch;

match(Client, Topic, [Rule|Rules]) ->
    case emqttd_access_rule:match(Client, Topic, Rule) of
        nomatch -> match(Client, Topic, Rules);
        {matched, AllowDeny} -> {matched, AllowDeny}
    end.

set_scopes(Client, []) ->
    Rules = [{deny,
              {client, Client#mqtt_client.client_id},
              publish,
              [<<"#">>]},
             {deny,
              {client, Client#mqtt_client.client_id},
              subscribe,
              [<<"#">>]}],
    ets:insert(?TAB, lists:map(fun emqttd_access_rule:compile/1, Rules));
set_scopes(Client, Scopes) ->
    case parse_scopes(Client, Scopes) of
        {ok, Rules} ->
            ets:insert(?TAB, Rules);
        {error, Reason} ->
            lager:error("cannot parse scopes: ~p", [Reason])
    end.

parse_scopes(Client, Scopes) ->
    parse_scopes(Client, Scopes, []).

parse_scopes(_Client, [], Acc) ->
    {ok, Acc};
parse_scopes(Client, [Scope|Scopes], Acc) ->
    case parse_scope(Client, Scope) of
        {ok, Rule} ->
            CR = emqttd_access_rule:compile(Rule),
            parse_scopes(Client, Scopes, [CR|Acc]);
        {error, Reason} ->
            {error, Reason}
    end.

parse_scope(Client, <<"emq:", Rest/binary>>) ->
    case Rest of
        <<"publish:", Topic/binary>> ->
            {ok,
             {allow,
              {client, Client#mqtt_client.client_id},
              publish, [Topic]}};
        <<"subscribe:", Topic/binary>> ->
            {ok,
             {allow,
              {client, Client#mqtt_client.client_id},
              subscribe, [Topic]}};
        _ ->
            {error, {invalid_action, Rest}}
    end;
parse_scope(_Client, Scope) ->
    {error, {invalid_service, Scope}}.
