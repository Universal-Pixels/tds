defmodule Tds.Tls do
  @moduledoc false
  use GenServer

  require Logger

  import Kernel, except: [send: 2]
  import Tds.BinaryUtils

  @default_ssl_opts [active: false, cb_info: {Tds.Tls, :tcp, :tcp_closed, :tcp_error}]

  defstruct [:socket, :ssl_opts, :owner_pid, :handshake?, :buffer, recv_buffer: <<>>]

  def connect(socket, ssl_opts) do
    ssl_opts = ssl_opts ++ @default_ssl_opts
    :inet.setopts(socket, active: false)

    with {:ok, pid} <- GenServer.start_link(__MODULE__, {socket, ssl_opts}, []),
         :ok <- :gen_tcp.controlling_process(socket, pid) do
      Logger.debug("[Tds.Tls] starting ssl.connect")
      connection_result = :ssl.connect(socket, ssl_opts, :infinity)
      Logger.debug("[Tds.Tls] ssl.connect returned: #{inspect(elem(connection_result, 0))}")

      # Check if ssl connection was established successfully
      if elem(connection_result, 0) == :ok do
        GenServer.cast(pid, :handshake_complete)
      end

      connection_result
    else
      error -> error
    end
  end

  def controlling_process(socket, tls_conn_pid) do
    case assert_connected!(socket) do
      :closed -> {:error, :closed}
      pid -> GenServer.call(pid, {:controlling_process, tls_conn_pid})
    end
  end

  def send(socket, payload) do
    case assert_connected!(socket) do
      :closed -> {:error, :closed}
      pid -> GenServer.call(pid, {:send, payload})
    end
  end

  def recv(socket, length, timeout \\ :infinity) do
    case assert_connected!(socket) do
      :closed -> {:error, :closed}
      pid -> GenServer.call(pid, {:recv, length, timeout}, timeout)
    end
  end

  defdelegate getopts(port, options), to: :inet

  # defdelegate setopts(socket, options), to: :inet
  def setopts(socket, options) do
    case assert_connected!(socket) do
      :closed -> {:error, :closed}
      pid -> GenServer.call(pid, {:setopts, options})
    end
  end

  defdelegate peername(socket), to: :inet

  :exports
  |> :gen_tcp.module_info()
  |> Enum.reject(fn {fun, arity} ->
    fun in [:send, :recv, :module_info, :controlling_process] or (fun == :connect and arity == 2)
  end)
  |> Enum.each(fn
    {name, 0} ->
      defdelegate unquote(name)(), to: :gen_tcp

    {name, 1} ->
      defdelegate unquote(name)(arg1), to: :gen_tcp

    {name, 2} ->
      defdelegate unquote(name)(arg1, arg2), to: :gen_tcp

    {name, 3} ->
      defdelegate unquote(name)(arg1, arg2, arg3), to: :gen_tcp

    {name, 4} ->
      defdelegate unquote(name)(arg1, arg2, arg3, arg4), to: :gen_tcp
  end)

  # Asserts that the port / socket is still open and returns its `pid` or :error atom for closed connections
  defp assert_connected!(socket) do
    case Port.info(socket, :connected) do
      {:connected, pid} -> pid
      nil -> :closed
    end
  end

  # SERVER
  def init({socket, ssl_opts}) do
    {:ok, %__MODULE__{socket: socket, ssl_opts: ssl_opts, handshake?: true}}
  end

  def handle_call({:controlling_process, tls_conn_pid}, _from, s) do
    Logger.debug("[Tds.Tls] controlling_process set to #{inspect(tls_conn_pid)}")
    {:reply, :ok, %{s | owner_pid: tls_conn_pid}}
  end

  def handle_call({:setopts, options}, _from, %{socket: socket, handshake?: hs} = s) do
    Logger.debug("[Tds.Tls] setopts(hs=#{hs}) #{inspect(options)}")
    {:reply, :inet.setopts(socket, options), s}
  end

  def handle_call({:send, data}, _from, %{socket: socket, handshake?: true} = s) do
    size = IO.iodata_length(data) + 8
    Logger.debug("[Tds.Tls] send(handshake) #{IO.iodata_length(data)} bytes")

    header = <<0x12, 0x01, size::unsigned-size(2)-unit(8), 0x00, 0x00, 0x00, 0x00>>

    resp = :gen_tcp.send(socket, [header, data])
    {:reply, resp, s}
  end

  def handle_call({:send, data}, _from, %{socket: socket, handshake?: false} = s) do
    resp = :gen_tcp.send(socket, data)
    {:reply, resp, s}
  end

  # During handshake, recv must strip TDS prelogin headers from server responses.
  # The server wraps each SSL handshake record in a TDS packet with an 8-byte header.
  # Without stripping, SSL sees 0x12 (TDS type) instead of 0x16 (SSL handshake).
  def handle_call({:recv, length, timeout}, _from, %{handshake?: true, recv_buffer: buf} = s) do
    Logger.debug("[Tds.Tls] recv(handshake) length=#{length} buf_size=#{byte_size(buf)}")
    case recv_handshake(s.socket, buf, length, timeout) do
      {:ok, data, rest} ->
        {:reply, {:ok, data}, %{s | recv_buffer: rest}}

      {:error, _} = error ->
        {:reply, error, s}
    end
  end

  def handle_call({:recv, length, timeout}, _from, %{socket: socket, handshake?: false} = s) do
    res = :gen_tcp.recv(socket, length, timeout)
    {:reply, res, s}
  end

  # If buffer already has enough data, return from buffer
  defp recv_handshake(_socket, buf, length, _timeout)
       when length > 0 and byte_size(buf) >= length do
    <<data::binary-size(length), rest::binary>> = buf
    {:ok, data, rest}
  end

  # If length is 0 and buffer has data, return all buffered data
  defp recv_handshake(_socket, buf, 0, _timeout) when byte_size(buf) > 0 do
    {:ok, buf, <<>>}
  end

  # Need to read from socket
  defp recv_handshake(socket, buf, length, timeout) do
    case :gen_tcp.recv(socket, 0, timeout) do
      {:ok, raw} ->
        new_data = strip_tds_header(raw)
        all_data = IO.iodata_to_binary([buf, new_data])

        cond do
          length == 0 ->
            {:ok, all_data, <<>>}

          byte_size(all_data) >= length ->
            <<data::binary-size(length), rest::binary>> = all_data
            {:ok, data, rest}

          true ->
            # Not enough data yet, read more
            recv_handshake(socket, all_data, length, timeout)
        end

      {:error, _} = error ->
        error
    end
  end

  # Strip 8-byte TDS prelogin header if present.
  # Server wraps SSL handshake data in: <<type(1), status(1), size(2), spid(2), packet(1), window(1)>>
  defp strip_tds_header(<<0x12, _status, _size::unsigned-16, _::32, payload::binary>>) do
    payload
  end

  defp strip_tds_header(data), do: data

  def handle_cast(:handshake_complete, s), do: {:noreply, %{s | handshake?: false, recv_buffer: <<>>}}

  def handle_info({:tcp, _, _} = msg, %{owner_pid: pid, handshake?: false, buffer: nil} = s) do
    Kernel.send(pid, msg)
    {:noreply, s}
  end

  def handle_info(
        {:tcp, port, <<0x12, 0, size::unsigned-16, _::32, tail::binary>>},
        %{socket: socket, owner_pid: pid, buffer: nil, handshake?: true} = s
      ) do
    Logger.debug("[Tds.Tls] handle_info(tcp, handshake, status=0) size=#{size}")
    expecting = size - 8

    case tail do
      <<ssl_payload::binary(expecting), next_packet::binary>> ->
        Kernel.send(pid, {:tcp, socket, ssl_payload})
        handle_info({:tcp, port, next_packet}, %{s | buffer: nil})

      next_slice ->
        state = %{s | buffer: {next_slice, expecting}}
        {:noreply, state}
    end
  end

  def handle_info(
        {:tcp, port, <<0x12, 1, size::unsigned-16, _::32, tail::binary>>},
        %{socket: socket, owner_pid: pid, buffer: nil, handshake?: true} = s
      ) do
    expecting = size - 8

    case tail do
      <<ssl_payload::binary(expecting), next_packet::binary>> ->
        Kernel.send(pid, {:tcp, socket, ssl_payload})
        handle_info({:tcp, port, next_packet}, %{s | buffer: nil})

      next_slice ->
        state = %{s | buffer: {next_slice, expecting}}
        {:noreply, state}
    end
  end

  def handle_info(
        {:tcp, port, bin},
        %{socket: socket, owner_pid: pid, buffer: {slice, expecting}, handshake?: true} = s
      ) do
    case IO.iodata_to_binary([slice, bin]) do
      <<ssl_payload::binary(expecting), next_packet::binary>> ->
        Kernel.send(pid, {:tcp, socket, ssl_payload})
        handle_info({:tcp, port, next_packet}, %{s | buffer: nil})

      next_slice ->
        state = %{s | buffer: {next_slice, expecting}}
        {:noreply, state}
    end
  end

  def handle_info({:tcp, _, _} = msg, %{owner_pid: pid, handshake?: true, buffer: nil} = s) do
    Kernel.send(pid, msg)
    {:noreply, s}
  end

  def handle_info(
        {:tcp_passive, _port} = msg,
        %{owner_pid: pid, handshake?: false, buffer: nil} = s
      ) do
    Kernel.send(pid, msg)
    {:noreply, s}
  end

  # During handshake, forward tcp_passive to the SSL process so it can
  # re-enable active mode. Without this, the socket goes passive and
  # the SSL handshake hangs waiting for data that never arrives.
  def handle_info(
        {:tcp_passive, _port} = msg,
        %{owner_pid: pid, handshake?: true} = s
      ) do
    Logger.debug("[Tds.Tls] handle_info(tcp_passive, handshake) - forwarding to SSL")
    Kernel.send(pid, msg)
    {:noreply, s}
  end

  def handle_info({tag, _} = msg, %{owner_pid: pid} = s) when tag in [:tcp_closed, :ssl_closed] do
    Kernel.send(pid, msg)
    {:stop, tag, s}
  end

  def handle_info({tag, _, _} = msg, %{owner_pid: pid} = s)
      when tag in [:tcp_error, :ssl_error] do
    Kernel.send(pid, msg)
    {:stop, tag, s}
  end

  # Catch-all for debugging unmatched messages
  def handle_info(msg, s) do
    Logger.debug("[Tds.Tls] UNMATCHED handle_info: #{inspect(msg, limit: 50)} state: hs=#{s.handshake?} owner=#{inspect(s.owner_pid)} buf=#{inspect(s.buffer)}")
    {:noreply, s}
  end
end
