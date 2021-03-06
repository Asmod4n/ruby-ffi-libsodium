﻿require 'ffi'
require_relative '../sodium/utils'
require_relative '../sodium/secret_buffer'

module Crypto
  module Auth
    extend FFI::Library
    extend Sodium::Utils

    ffi_lib :libsodium

    attach_function :primitive, :crypto_auth_primitive, [], :string
    attach_function :bytes,     :crypto_auth_bytes,     [], :size_t
    attach_function :keybytes,  :crypto_auth_keybytes,  [], :size_t

    PRIMITIVE = primitive.freeze
    BYTES     = bytes.freeze
    KEYBYTES  = keybytes.freeze

    attach_function :crypto_auth,         [:buffer_out, :buffer_in, :ulong_long, :buffer_in], :int
    attach_function :crypto_auth_verify,  [:buffer_in, :buffer_in, :ulong_long, :buffer_in],  :int

    module_function

    def auth(message, key)
      check_length(key, KEYBYTES, :SecretKey)

      mac = zeros(BYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_auth(mac, message, get_size(message), key)

      mac
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def verify(mac, message, key)
      check_length(mac, BYTES, :Mac)
      check_length(key, KEYBYTES, :SecretKey)

      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_auth_verify(mac, message, get_size(message), key) == 0
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end
  end

  Auth.freeze

  module_function

  def auth(*args)
    Auth.auth(*args)
  end
end
