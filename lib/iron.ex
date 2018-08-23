defmodule Iron do
  @moduledoc """
  Serialize and encrypt any Elixir `term()` and send it around.

  ## Examples

      iex> Iron.seal(%{"very" => "secret"}, "password")
      {:error, "password string too short (min 32 characters required)"}

      iex> sealed = Iron.seal(%{"a" => 1, "b" => 2, "c" => [3, 4, 5], "d" => %{ "e" => "f" }}, "some_not_random_password_that_is_also_long_enough")
      iex> Iron.unseal(sealed, "some_not_random_password_that_is_also_long_enough")
      %{"a" => 1, "b" => 2, "c" => [3, 4, 5], "d" => %{ "e" => "f" }}
  """
  use Bitwise

  @typedoc false
  @type password :: iodata() | %{id: iodata(), secret: iodata()} | %{id: iodata(), encryption: iodata(), integrity: iodata()}

  @typedoc """
  These are the Iron defualts it is recommended to use the defualts
  """
  @type defaults :: %{encryption: %{algorithm: :aes_cbc256, iterations: 1, iv_bits: 128, key_bits: 256, min_password_length: 32, salt_bits: 256},
                      integrity:  %{algorithm: :sha256, iterations: 1, key_bits: 256, min_password_length: 32, salt_bits: 256},
                      ttl: 0, timestamp_skew_sec: 60, localtime_offset_msec: 0}

  @doc false
  @spec algorithms() :: %{aes_ctr128: %{key_bits: 128, iv_bits: 128}, aes_cbc256: %{key_bits: 256, iv_bits: 128}, sha256: %{key_bits: 256}}
  def algorithms(), do: %{aes_ctr128: %{key_bits: 128, iv_bits: 128}, aes_cbc256: %{key_bits: 256, iv_bits: 128}, sha256: %{key_bits: 256}}

  # aes_ctr128 is supported if you want you use aes_ctr128 then you can use the map below
  # @aes_ctr128 %{iterations: 10000, iv_bits: 128, key_bits: 128, min_password_length: 32, salt_bits: 256}
  @aes_cbc256 %{algorithm: :aes_cbc256, iterations: 1, iv_bits: 128, key_bits: 256, min_password_length: 32, salt_bits: 256}
  @sha256 %{algorithm: :sha256, iterations: 1, key_bits: 256, min_password_length: 32, salt_bits: 256}

  @defaults %{encryption: @aes_cbc256, integrity: @sha256, ttl: 0, timestamp_skew_sec: 60, localtime_offset_msec: 0}
  @doc false
  def defaults(), do: @defaults

  @mac_format_version "2"
  @mac_prefix "Fe26." <> @mac_format_version

  @doc false
  def mac_prefix(), do: @mac_prefix

  @doc false
  @spec generate_key(binary(), keyword() | map()) :: map() | {:error, term()}
  def generate_key(password, options) when is_list(options), do: generate_key(password, Map.new(options))
  def generate_key(password, _options) when not is_binary(password) and not is_list(password), do: {:error, {500, "Invalid password #{inspect password}"}}
  def generate_key([], _options), do: {:error, {500, "Empty password"}}
  def generate_key(<<>>, _options), do: {:error, {500, "Empty password"}}
  def generate_key(_password, %{algorithm: algorithm}) when algorithm not in [:aes_ctr128, :aes_cbc256, :sha256] do
    {:error, {500, "Unknown algorithm: #{inspect algorithm}"}}
  end
  def generate_key(password, %{key_bits: key_bits, min_password_length: min_password_length} = options) when is_binary(password) do
    case String.valid?(password) do
      false when byte_size(password) < div(key_bits, 8)    -> {:error, {500, "Key buffer (password) too small"}}

      true  when byte_size(password) < min_password_length -> {:error, {500, "Password string too short (min #{min_password_length} characters required)"}}

      false ->  maybe_add_iv(%{key: password, salt: ""} , options)

      true  -> __generate_key__(password, options)
    end
  end
  def generate_key(password, %{min_password_length: min_password_length}) when is_list(password) and length(password) < min_password_length do
    {:error, {500, "Password too short (min #{min_password_length} characters required)"}}
  end
  def generate_key(_password, %{algorithm: _, iterations: _, key_bits: _, min_password_length: _}), do: {:error, {500, "Missing salt or salt_bits options"}}
  def generate_key(_password, _option), do: {:error, {500, "Bad options"}}

  defp __generate_key__(password, %{iterations: iterations, key_bits: key_bits, salt: salt} = options) do
    derived_key = Kryptiles.pbkdf2(password, salt, div(key_bits, 8), iterations)
    maybe_add_iv(%{key: derived_key, salt: salt}, options)
  end
  defp __generate_key__(password, %{iterations: iterations, key_bits: key_bits, salt_bits: salt_bits} = options) do
    case Kryptiles.random_bits(salt_bits) do
      {:error, reason} -> {:error, reason}

      bytes            ->
        salt = Base.hex_encode32(bytes)
        derived_key = Kryptiles.pbkdf2(password, salt, div(key_bits, 8), iterations)
        maybe_add_iv(%{key: derived_key, salt: salt}, options)
    end
  end
  defp __generate_key__(_password, %{algorithm: _, iterations: _, key_bits: _, min_password_length: _}), do: {:error, {500, "Missing salt or salt_bits options"}}
  defp __generate_key__(_password, _option), do: {:error, {500, "Bad options"}}

  defp maybe_add_iv(result, %{iv: iv}), do: Map.put(result, :iv, iv)
  defp maybe_add_iv(result, %{iv_bits: iv_bits}) do
    case Kryptiles.random_bits(iv_bits) do
      {:error, reason} -> {:error, reason}

      iv               -> Map.put(result, :iv, iv)
    end
  end
  defp maybe_add_iv(result, _), do: result

  @doc false
  @spec encrypt(binary(), map(), binary()) :: %{encrypted: binary(), key: map()} | {:error, binary()}
  def encrypt(password, %{algorithm: algorithm} = options, data) do
    case generate_key(password, options) do
      {:error, reason}              -> {:error, reason}

      %{iv: iv, key: gen_key} = key ->
      encrypted = :crypto.block_encrypt(algorithm, gen_key, iv, padding(data))
      %{encrypted: encrypted, key: key}
    end
  end

  @doc false
  @spec decrypt(binary(), map(), binary()) :: binary() | {:error, binary()}
  def decrypt(password, %{algorithm: algorithm} = options, data) do
    case generate_key(password, options) do
      {:error, reason}        -> {:error, reason}

      %{iv: iv, key: gen_key} -> :crypto.block_decrypt(algorithm, gen_key, iv, data)
      end
  end

  @doc false
  @spec hmac(binary(), map(), binary()) :: %{digest: binary(), salt: binary()} | {:error, binary()}
  def hmac(password, %{algorithm: algorithm} = options, data) do
    case generate_key(password, options) do
      {:error, reason}            -> {:error, reason}

      %{key: gen_key, salt: salt} ->
        hmac = :crypto.hmac(algorithm, gen_key, data)
        digest = hmac |> Base.encode64() |> __encode__()
        %{digest: digest, salt: salt}
    end
  end

  defp __encode__(binary, result \\ <<>>)
  defp __encode__(<<>>, result), do: result
  for {pattern, replacment} <- [{?+, ?-}, {?/, ?_}, {?=, <<>>}] do
    defp __encode__(<<unquote(pattern), rest::binary()>>, result), do: __encode__(rest, <<result::binary(), unquote(replacment)>>)
  end
  defp __encode__(<<b, rest::binary()>>, result), do: __encode__(rest, <<result::binary(), b>>)

  @doc """
  Encrypt and HMAC a `term()`
  """
  @spec seal(term(), password(), keyword() | map()) :: binary() | {:error, binary()}
  def seal(term, password, options \\ @defaults)
  def seal(term, password, options) when is_list(options), do: seal(term, password, Map.new(options))
  def seal(term, password, options) do
    now = System.system_time(1000) + (options[:localtime_offset_msec] || 0)
    term
    |> Jason.encode()
    |> __seal__(now, password, options)
  end

  defp __seal__({:error, reason}, _now, _password, _options), do: {:error, reason}
  defp __seal__({:ok, binary}, now, password, options) do
    case normalize_password(password) do
      {:error, reason} -> {:error, reason}

      %{id: id, encryption: encryption, integrity: integrity} ->
        case encrypt(encryption, options[:encryption], binary) do
          {:error, reason}                                    -> {:error, reason}

          %{encrypted: encrypted, key: %{iv: iv, salt: salt}} ->
            encrypted_b64 = Base.url_encode64(encrypted, padding: false)
            iv = Base.url_encode64(iv, padding: false)
            expiration = if options[:ttl], do: now + options[:ttl], else: ""
            mac_base_string = "#{@mac_prefix}*#{id}*#{salt}*#{iv}*#{encrypted_b64}*#{expiration}"
            case hmac(integrity, options[:integrity], mac_base_string) do
              {:error, reason}                  -> {:error, reason}

              %{salt: mac_salt, digest: digest} ->
              "#{mac_base_string}*#{mac_salt}*#{digest}"
            end
        end
    end
  end

  @doc """
  Decrypt and validate a sealed `binary()`
  """
  @spec unseal(binary(), password(), keyword() | map()) :: term() | {:error, binary()}
  def unseal(sealed, password, options \\ @defaults)
  def unseal(sealed, password, options) when is_list(options), do: unseal(sealed, password, Map.new(options))
  def unseal(sealed, password, options) do
    now = System.system_time(1000) + (options[:localtime_offset_msec] || 0)
    case :string.split(sealed, '*', :all) do
      parts when length(parts) !== 8                   -> {:error, {500, "Incorrect number of sealed components"}}

      [mac_prefix | _] when mac_prefix !== @mac_prefix -> {:error, {500, "Wrong mac prefix"}}

      parts ->
        [:mac_prefix, :password_id, :encryption_salt, :encryption_iv, :encrypted_b64, :expiration, :hmac_salt, :hmac]
        |> Enum.zip(parts)
        |> Enum.into(%{})
        |> maybe_validate_expiration(now, options)
        |> __unseal__(password, options)
      end
  end

  defp maybe_validate_expiration(%{expiration: ""} = parts, _now, _options), do: parts
  defp maybe_validate_expiration(%{expiration: expiration} = parts, now, options) do
    skew = options[:timestamp_skew_sec]
    case :string.to_integer(expiration) do
      {exp, ""} when exp <= (now - (skew * 1000)) -> {:error, {500, "Expired seal"}}

      {_exp, ""}                                  -> parts

      {_, _}                                      -> {:error, {500, "Invalid expiration"}}
    end
  end

  defp __unseal__({:error, reason}, _password_or_parts, _options), do: {:error, reason}
  defp __unseal__(%{id: id}, %{password_id: password_id}, _options) when id !== password_id do
    {:error, {500, "Cannot find password: #{password_id}"}}
  end
  defp __unseal__(%{encryption: encryption, integrity: integrity}, %{mac_prefix: mac_prefix, password_id: password_id, encryption_salt: encryption_salt, encryption_iv: encryption_iv, encrypted_b64: encrypted_b64, expiration: expiration, hmac_salt: hmac_salt} = parts, options) do
    mac_base_string = <<mac_prefix::binary(), ?*, password_id::binary(), ?*, encryption_salt::binary(), ?*, encryption_iv::binary(), ?*, encrypted_b64::binary(), ?*, expiration::binary()>>
    hmac_opts = Map.put(options[:integrity], :salt, hmac_salt)

    integrity
    |> hmac(hmac_opts, mac_base_string)
    |> __unseal__(encryption, parts, options)
  end
  defp __unseal__(parts, password, options) do
    password
    |> normalize_password()
    |> __unseal__(parts, options)
  end
  defp __unseal__(%{digest: digest}, encryption, %{hmac: hmac} = parts, options) do
    digest
    |> Kryptiles.fixed_time_comparison(hmac)
    |> maybe_decrypt(encryption, parts, options)
  end
  defp __unseal__(error, _encryption, _parts, _options), do: error

  defp maybe_decrypt(false, _encryption, _parts, _options), do: {:error, {500, "Bad hmac value"}}
  defp maybe_decrypt(true, encryption, %{encryption_salt: encryption_salt, encryption_iv: encryption_iv, encrypted_b64: encrypted_b64}, options) do
    case url_decode64(encrypted_b64, encryption_iv) do
      {:error, reason}           -> {:error, reason}

      {enc, iv} ->
        decrypt_opts = Map.merge(options[:encryption], %{salt: encryption_salt, iv: iv})

        encryption
        |> decrypt(decrypt_opts, enc)
        |> unpadding()
        |> decode_json()
    end
  end

  def decode_json(:error), do: {:error, {500, "Failed parsing sealed object JSON"}}
  def decode_json(msg) do
    case Jason.decode(msg, keys: &mixed_keys/1) do
      {:error, _} -> {:error, {500, "Failed parsing sealed object JSON"}}

      {:ok, map}  -> map
    end
  end

  defp mixed_keys(key) do
    try do
      String.to_existing_atom(key)
    rescue
      ArgumentError -> key
    end
  end

  defp url_decode64({:ok, encrypted}, {:ok, encryption_iv}), do: {encrypted, encryption_iv}
  defp url_decode64(enc, iv) when is_binary(enc) and is_binary(iv) do
    enc
    |> Base.url_decode64(padding: false)
    |> url_decode64(Base.url_decode64(iv, padding: false))
  end
  defp url_decode64(_, _), do: {:error, {500, "Invalid character"}}

  defp normalize_password(%{id: id, encryption: _, integrity: _} = password) do
    case String.match?(id, ~r/^\w+$/) do
      false -> {:error, {500, "Invalid password id: #{inspect id}"}}

      true  -> password
    end

  end
  defp normalize_password(%{id: id, secret: secret}) do
    case String.match?(id, ~r/^\w+$/) do
      false -> {:error, {500, "Invalid password id: #{inspect id}"}}

      true  -> %{id: id, encryption: secret, integrity: secret}
    end
  end
  defp normalize_password(""), do: {:error, {500, "Empty password"}}
  defp normalize_password(''), do: {:error, {500, "Empty password"}}
  defp normalize_password(password) when is_binary(password) or is_list(password), do: %{id: <<>>, encryption: password, integrity: password}
  defp normalize_password(password), do: {:error, {500, "Invalid password #{inspect password}"}}

  # https://tools.ietf.org/html/rfc2315
  defp padding(message) do
    padding_size = 16 - rem(byte_size(message), 16)
    message <> :binary.copy(<<padding_size>>, padding_size)
  end
  defp unpadding(<<>>), do: :error
  defp unpadding(message) do
    padding_size = :binary.last(message)
    padding = byte_size(message) - padding_size
    case padding_size <= 16 do
      true  -> :erlang.binary_part(message, 0, padding)

      false -> :error
    end
  end
end

