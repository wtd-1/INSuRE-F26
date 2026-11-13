#!/usr/bin/env escript

main([PortStr, CertFilename, KeyFilename]) ->
  Port = list_to_integer(PortStr),
  ssl:start(),
  io:format("[~p] listen\n", [self()]),
  {ok, ListenSocket} = ssl:listen(Port, [{active, false},
                                         {certfile, CertFilename},
                                         {keyfile, KeyFilename},
                                         {reuseaddr, true},
                                         {versions, [tlsv1, 'tlsv1.1', 'tlsv1.2']},
                                         {client_renegotiation, false}
                                        ]),
  listen_to_clients(ListenSocket).

listen_to_clients(ListenSocket) ->
  io:format("[~p] accept\n", [self()]),
  {ok, TLSTransportSocket} = ssl:transport_accept(ListenSocket),
  io:format("[~p] handshake\n", [self()]),
  case ssl:ssl_accept(TLSTransportSocket, 5000) of
    ok ->
      io:format("[~p] spawn\n", [self()]),
      Pid = spawn (fun () -> handle_client(TLSTransportSocket) end),
      io:format("[~p] spawned ~p~n", [self(), Pid]);
    {error, Reason} ->
      io:format("[~p] Error (Reason: ~p)\n", [self(), Reason])
  end,
  listen_to_clients(ListenSocket).

handle_client(Socket) ->
  io:format("[~p] recv\n", [self()]),
  case ssl:recv(Socket, 0) of
    {ok, Data} ->
      io:format("[~p] send\n", [self()]),
      ssl:send(Socket, "200 HTTP/1.0 OK\r\nContent-Type: text/plain\r\n\r\n"),
      ssl:send(Socket, Data),
      handle_client(Socket);
    {error, Reason} ->
      io:format("[~p] Connection closed (Reason: ", [self()]),
      io:format(Reason),
      io:format(")\n"),
      ssl:close(Socket)
  end.
