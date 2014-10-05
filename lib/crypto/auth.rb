require_relative '../sodium'
require_relative '../sodium/utils'
require_relative '../sodium/buffer'
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

    attach_function :crypto_auth,         [:buffer_out, :buffer_in, :ulong_long, :buffer_in], :int, blocking: true
    attach_function :crypto_auth_verify,  [:buffer_in, :buffer_in, :ulong_long, :buffer_in],  :int, blocking: true

    module_function

    def auth(message, key)
      message_len = get_size(message)
      check_length(key, KEYBYTES, :SecretKey)

      mac = Sodium::Buffer.new(:uchar, BYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_auth(mac, message, message_len, key)
      key.noaccess if key.is_a?(Sodium::SecretBuffer)

      mac
    end

    def verify(mac, message, key)
      check_length(mac, BYTES, :Mac)
      message_len = get_size(message)
      check_length(key, KEYBYTES, :SecretKey)

      key.readonly if key.is_a?(Sodium::SecretBuffer)
      rc = crypto_auth_verify(mac, message, message_len, key)
      key.noaccess if key.is_a?(Sodium::SecretBuffer)

      rc == 0
    end
  end

  def self.auth(*args)
    Auth.auth(*args)
  end
end
