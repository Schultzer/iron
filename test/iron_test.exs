defmodule IronTest do
  use ExUnit.Case
  # doctest Iron

  setup do
    [password: "some_not_random_password_that_is_also_long_enough", map: %{a: 1, b: 2, c: [3, 4, 5], d: %{e: "f" }}]
  end

  test "turns map into a ticket than parses the ticket successfully", %{password: password, map: map} do
    sealed = Iron.seal(map, password)
    unseal = Iron.unseal(sealed, password)
    assert unseal == map
  end

  test "unseal and sealed map with expiration", %{password: password, map: map} do
    sealed = Iron.seal(map, password, %{Iron.defaults() | ttl: 200})
    # passowrd = %{"default" => password}
    unseal = Iron.unseal(sealed, password)
    assert unseal == map
  end

  test "unseal and sealed map with expiration and time offset", %{password: password, map: map} do
    sealed = Iron.seal(map, password, %{Iron.defaults() | ttl: 200, localtime_offset_msec: -10_000})
    # passowrd = %{"default" => password}
    unseal = Iron.unseal(sealed, password, %{Iron.defaults() | localtime_offset_msec: -10_000})
    assert unseal == map
  end

  test "turns map into a ticket than parses the ticket successfully binary", %{map: map} do
    key = Kryptiles.random_bits(256)
    sealed = Iron.seal(map, key)
    unseal = Iron.unseal(sealed, key)
    assert unseal == map
  end

  test "fails to turns map into a ticket password too short", %{password: password, map: map}  do
    key = Kryptiles.random_bits(128)
    sealed = Iron.seal(map, password)
    assert Iron.unseal(sealed, key) == {:error, {500, "Key buffer (password) too small"}}
  end

  # test "fails to turn map into a ticket (failed to stringify map)" do
  #   key = Kryptiles.random_bits(128)
  #   assert Iron.seal([], key) == {:error, "Failed to stringify object"}
  # end

  test "turns map into a ticket than parses the ticket successfully (password map)", %{password: password, map: map} do
    passoword = %{id: "1", secret: password}
    sealed = Iron.seal(map, passoword)
    unseal = Iron.unseal(sealed, passoword)
    assert unseal == map
  end

  test "handles separate password map", %{map: map} do
    key = %{id: "1", encryption: Kryptiles.random_bits(256), integrity: Kryptiles.random_bits(256)}
    sealed = Iron.seal(map, key)
    unseal = Iron.unseal(sealed, key)
    assert unseal == map
  end

  test "handles a common password map", %{map: map} do
    key = %{id: "1", secret: Kryptiles.random_bits(256)}
    sealed = Iron.seal(map, key)
    unseal = Iron.unseal(sealed, key)
    assert unseal == map
  end

  test "fails to parse a sealed object when password not found", %{password: password, map: map} do
    sealed = Iron.seal(map, %{id: "1", secret: password})
    assert Iron.unseal(sealed, %{id: "2", secret: password}) == {:error, {500, "Cannot find password: 1"}}
  end

  describe "generate_key/2" do
    test "returns an error when password is invalid" do
      assert Iron.generate_key(nil, nil) == {:error, {500, "Invalid password nil"}}
    end

    test "returns an error when password is empty" do
      assert Iron.generate_key(<<>>, nil) == {:error, {500, "Empty password"}}
      assert Iron.generate_key([], nil) == {:error, {500, "Empty password"}}
    end

    test "returns an error when password is too short" do
      assert Iron.generate_key('password', Iron.defaults.encryption) == {:error, {500, "Password too short (min 32 characters required)"}}
      assert Iron.generate_key("password", Iron.defaults.encryption) == {:error, {500, "Password string too short (min 32 characters required)"}}
    end

    test "returns an error when options are missing", %{password: password} do
      assert Iron.generate_key(password, nil) == {:error, {500, "Bad options"}}
    end

    test "returns an error when an unknown algorithm is specified", %{password: password} do
      assert Iron.generate_key(password, %{Iron.defaults.encryption | algorithm: "unknown"}) == {:error, {500, "Unknown algorithm: \"unknown\""}}
    end

    test "returns an error when no salt or salt bits are provided", %{password: password} do
      assert Iron.generate_key(password, Map.delete(Iron.defaults.encryption, :salt_bits)) == {:error, {500, "Missing salt or salt_bits options"}}
    end

    test "returns an error when invalid salt bits are provided", %{password: password} do
      assert Iron.generate_key(password, %{Iron.defaults.integrity | iterations: 2, salt_bits: 99999999999999999999}) == {:error, "failed generating random bits"}
    end

    test "returns an error when Kryptiles.random_bits/1 fails", %{password: password} do
      options = Map.put(%{Iron.defaults.encryption | iv_bits:  -1}, :salt, "abcdefg")
      assert Iron.generate_key(password, options) == {:error, "invalid random bits count"}
    end
  end

  describe "encrypt/2" do
    test "returns an error when password is missing" do
      assert Iron.encrypt(<<>>, Iron.defaults.encryption, "data") == {:error, {500, "Empty password"}}
      assert Iron.encrypt([], Iron.defaults.encryption, "data") == {:error, {500, "Empty password"}}
    end
  end

  describe "decrypt/2" do
    test "returns an error when password is missing" do
      assert Iron.decrypt(<<>>, Iron.defaults.encryption, "data") == {:error, {500, "Empty password"}}
      assert Iron.decrypt([], Iron.defaults.encryption, "data") == {:error, {500, "Empty password"}}
    end
  end

  describe "hmac/2" do
    test "returns an error when password is missing" do
      assert Iron.hmac(<<>>, Iron.defaults.integrity, "data") == {:error, {500, "Empty password"}}
      assert Iron.hmac([], Iron.defaults.integrity, "data") == {:error, {500, "Empty password"}}
    end

    test "produces the same mac when used with binary password" do
      data = "not so random"
      key = Kryptiles.random_bits(256)
      options = Iron.defaults.integrity
      mac = Iron.hmac(key, options, data)
      digest = :crypto.hmac(options.algorithm, key, data) |>  Base.encode64() |> String.replace(~r/\+/, "-") |> String.replace(~r/\//, "_") |> String.replace(~r/\=/, "")
      assert digest == mac.digest
    end
  end

  describe "seal/2" do
    test "returns an error when password is invalid" do
      assert Iron.seal("data", nil) == {:error, {500, "Invalid password nil"}}
    end

    test "returns an error when password is empty" do
      assert Iron.seal("data", []) == {:error, {500, "Empty password"}}
      assert Iron.seal("data", <<>>) == {:error, {500, "Empty password"}}
    end

    test "returns an error when integrity options are missing", %{password: password} do
      assert Iron.seal("data", password, %{encryption: %{algorithm: "x"}}) == {:error, {500, "Unknown algorithm: \"x\""}}
    end

    test "returns an error when password.id is invalid" do
      assert Iron.seal("data", %{id: "asd$", secret: "asd"}) == {:error, {500, "Invalid password id: \"asd$\""}}
    end
  end

  describe "unseal/2" do
    test "unseals a ticket", %{password: password, map: map} do
      ticket = "Fe26.2**0cdd607945dd1dffb7da0b0bf5f1a7daa6218cbae14cac51dcbd91fb077aeb5b*aOZLCKLhCt0D5IU1qLTtYw*g0ilNDlQ3TsdFUqJCqAm9iL7Wa60H7eYcHL_5oP136TOJREkS3BzheDC1dlxz5oJ**05b8943049af490e913bbc3a2485bee2aaf7b823f4c41d0ff0b7c168371a3772*R8yscVdTBRMdsoVbdDiFmUL8zb-c3PQLGJn4Y8C-AqI"
      unsealed = Iron.unseal(ticket, password)
      assert unsealed == map
    end

    test "returns an error when number of sealed components is wrong", %{password: password} do
      ticket = "x*Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU"
      assert Iron.unseal(ticket, password) == {:error, {500, "Incorrect number of sealed components"}}
    end

    test "returns an error when password is invalid" do
      ticket = "Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU"
      assert Iron.unseal(ticket, nil) == {:error, {500, "Invalid password nil"}}
    end

    test "returns an error when password is missing" do
      ticket = "Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU"
      assert Iron.unseal(ticket, <<>>) == {:error, {500, "Empty password"}}
      assert Iron.unseal(ticket, []) == {:error, {500, "Empty password"}}
    end

    test "returns an error when mac prefix is wrong", %{password: password} do
      ticket = "Fe27.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU"
      assert Iron.unseal(ticket, password) == {:error, {500, "Wrong mac prefix"}}
    end

    test "returns an error when integrity check fails", %{password: password} do
      ticket = "Fe26.2**b3ad22402ccc60fa4d527f7d1c9ff2e37e9b2e5723e9e2ffba39a489e9849609*QKCeXLs6Rp7f4LL56V7hBg*OvZEoAq_nGOpA1zae-fAtl7VNCNdhZhCqo-hWFCBeWuTTpSupJ7LxQqzSQBRAcgw**72018a21d3fac5c1608a0f9e461de0fcf17b2befe97855978c17a793faa01db1*Qj53DFE3GZd5yigt-mVl9lnp0VUoSjh5a5jgDmod1EZ"
      assert Iron.unseal(ticket, password) == {:error, {500, "Bad hmac value"}}
    end

    test "returns an error when decryption fails", %{password: password} do
      mac_base_string = "Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M??*"
      options = Map.put(Iron.defaults.integrity, :salt, "ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5")
      mac = Iron.hmac(password, options, mac_base_string)
      ticket = "#{mac_base_string}*#{options.salt}*#{mac.digest}"
      assert Iron.unseal(ticket, password) == {:error, {500, "Invalid character"}}
    end

    test "returns an error when iv base64 decoding fails", %{password: password} do
      mac_base_string = "Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw??*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M*"
      options = Map.put(Iron.defaults.integrity, :salt, "ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5")
      mac = Iron.hmac(password, options, mac_base_string)
      ticket = "#{mac_base_string}*#{options.salt}*#{mac.digest}"
      assert Iron.unseal(ticket, password) == {:error, {500, "Invalid character"}}
    end

    test "returns an error when decrypted object is invalid", %{password: password} do
      bad_json = "{asdasd"
      %{encrypted: encrypted, key: %{iv: iv, salt: salt}} = Iron.encrypt(password, Iron.defaults.encryption, bad_json)
      mac_base_string = Iron.mac_prefix() <> "**" <> salt <> "*" <> Base.url_encode64(encrypted, padding: false) <> "*" <> Base.url_encode64(iv, padding: false) <> "*"
      %{digest: digest, salt: hmac_salt} = Iron.hmac(password, Iron.defaults.integrity, mac_base_string)
      ticket = "#{mac_base_string}*#{hmac_salt}*#{digest}"
      assert Iron.unseal(ticket, password) == {:error, {500, "Failed parsing sealed object JSON"}}
    end

    test "returns an error when expired", %{password: password} do
      mac_base_string = "Fe26.2**a38dc7a7bf2f8ff650b103d8c669d76ad219527fbfff3d98e3b30bbecbe9bd3b*nTsatb7AQE1t0uMXDx-2aw*uIO5bRFTwEBlPC1Nd_hfSkZfqxkxuY1EO2Be_jJPNQCqFNumRBjQAl8WIKBW1beF*1380495854060"
      integrity = Map.put(Iron.defaults.integrity, :salt, "e4fe33b6dc4c7ef5ad7907f015deb7b03723b03a54764aceeb2ab1235cc8dce3")
      mac = Iron.hmac(password, integrity, mac_base_string)
      ticket = "#{mac_base_string}*#{integrity.salt}*#{mac.digest}"
      assert Iron.unseal(ticket, password) == {:error, {500, "Expired seal"}}
    end

    test "returns an error when expiration NaN", %{password: password} do
      mac_base_string = "Fe26.2**a38dc7a7bf2f8ff650b103d8c669d76ad219527fbfff3d98e3b30bbecbe9bd3b*nTsatb7AQE1t0uMXDx-2aw*uIO5bRFTwEBlPC1Nd_hfSkZfqxkxuY1EO2Be_jJPNQCqFNumRBjQAl8WIKBW1beF*a"
      integrity = Map.put(Iron.defaults.integrity, :salt, "e4fe33b6dc4c7ef5ad7907f015deb7b03723b03a54764aceeb2ab1235cc8dce3")
      mac = Iron.hmac(password, integrity, mac_base_string)
      ticket = "#{mac_base_string}*#{integrity.salt}*#{mac.digest}"
      assert Iron.unseal(ticket, password) == {:error, {500, "Invalid expiration"}}
    end
  end
end
