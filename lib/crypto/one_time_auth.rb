require 'ffi'
require_relative '../sodium/utils'
require_relative '../sodium/secret_buffer'

module Crypto
  module OneTimeAuth
    extend FFI::Library
    extend Sodium::Utils

    ffi_lib :libsodium

    attach_function :primitive, :crypto_onetimeauth_primitive, [], :string
    attach_function :bytes,     :crypto_onetimeauth_bytes,     [], :size_t
    attach_function :keybytes,  :crypto_onetimeauth_keybytes,  [], :size_t

    PRIMITIVE = primitive.freeze
    BYTES     = bytes.freeze
    KEYBYTES  = keybytes.freeze

    attach_function :crypto_onetimeauth,        [:buffer_out, :buffer_in, :ulong_long, :buffer_in], :int
    attach_function :crypto_onetimeauth_verify, [:buffer_in, :buffer_in, :ulong_long, :buffer_in],  :int

    class State < FFI::Struct
      layout  :aligner, :ulong_long,
              :opaque,  [:uchar, 136]
    end

    attach_function :crypto_onetimeauth_init,   [State.ptr, :buffer_in],              :int
    attach_function :crypto_onetimeauth_update, [State.ptr, :buffer_in, :ulong_long], :int
    attach_function :crypto_onetimeauth_final,  [State.ptr, :buffer_out],             :int

    module_function

    def onetimeauth(message, key)
      check_length(key, KEYBYTES, :SecretKey)

      mac = zeros(BYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_onetimeauth(mac, message, get_size(message), key)

      mac
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def verify(mac, message, key)
      check_length(mac, BYTES, :Mac)
      check_length(key, KEYBYTES, :SecretKey)

      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_onetimeauth_verify(mac, message, get_size(message), key) == 0
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def init(key)
      check_length(key, KEYBYTES, :SecretKey)

      state = State.new
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_onetimeauth_init(state, key)

      state
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def update(state, message)
      crypto_onetimeauth_update(state, message, get_size(message))
    end

    def final(state)
      mac = zeros(BYTES)
      crypto_onetimeauth_final(state, mac)
      mac
    end
  end

  OneTimeAuth.freeze

  module_function

  def onetimeauth(*args)
    OneTimeAuth.onetimeauth(*args)
  end
end
