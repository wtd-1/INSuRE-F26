#!/usr/bin/env escript

main([VersionStr, PortStr, CertFilename, KeyFilename]) ->
  Port = list_to_integer(PortStr),
  Version = case VersionStr of
    "tlsv1" -> tlsv1;
    "tlsv1.1" -> 'tlsv1.1';
    "tlsv1.2" -> 'tlsv1.2';
    "tlsv1.3" -> 'tlsv1.3'
  end,
  ssl:start(),
  if
    Version == 'tlsv1.3' ->
  {ok, ListenSocket} = ssl:listen(Port, [{certfile, CertFilename},
                                         {keyfile, KeyFilename},
                                         {reuseaddr, true},
                                         {versions, [Version]},
                                         {ciphers, ssl:cipher_suites(all, Version)}
					]);
    true ->
  {ok, ListenSocket} = ssl:listen(Port, [{certfile, CertFilename},
                                         {keyfile, KeyFilename},
					 {client_renegotiation, false},
                                         {reuseaddr, true},
                                         {versions, [Version]},
                                         {ciphers, ssl:cipher_suites(all, Version)}
                                        ])
  end,
  listen_to_clients(ListenSocket).

listen_to_clients(ListenSocket) ->
  {ok, TLSTransportSocket} = ssl:transport_accept(ListenSocket),
  case ssl:handshake(TLSTransportSocket) of
    {ok, Socket} ->
      Handler = spawn(fun() -> handle_client() end),
      ssl:controlling_process(Socket, Handler);
    {error, Reason} ->
      ok
  end,
  listen_to_clients(ListenSocket).

handle_client() ->
  receive
    {ssl, Socket, Data} ->
      ssl:send(Socket, "200 HTTP/1.0 OK\r\nContent-Type: text/plain\r\n\r\n"),
      ssl:send(Socket, Data),
      handle_client();
    {ssl_closed, Socket} ->
      ssl:close(Socket);
    {ssl_error, Socket, Reason} ->
      io:fwrite(Reason),
      ssl:close(Socket)
  end.
