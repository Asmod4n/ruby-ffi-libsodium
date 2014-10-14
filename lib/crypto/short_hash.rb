require 'ffi'
require_relative '../sodium/utils'
require_relative '../sodium/buffer'
require_relative '../sodium/secret_buffer'

module Crypto
  module ShortHash
    extend FFI::Library
    extend Sodium::Utils

    ffi_lib :libsodium

    attach_function :primitive, :crypto_shorthash_primitive,  [], :string
    attach_function :bytes,     :crypto_shorthash_bytes,      [], :size_t
    attach_function :keybytes,  :crypto_shorthash_keybytes,   [], :size_t

    PRIMITIVE = primitive.freeze
    BYTES     = bytes.freeze
    KEYBYTES  = keybytes.freeze

    attach_function :crypto_shorthash,  [:buffer_out, :buffer_in, :ulong_long, :buffer_in], :int, blocking: true

    module_function

    def shorthash(short_data, key)
      short_data_len = get_size(short_data)
      check_length(key, KEYBYTES, :SecretKey)

      siphash = Sodium::Buffer.new(:uchar, BYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_shorthash(siphash, short_data, short_data_len, key)

      siphash
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end
  end

  module_function

  def shorthash(*args)
    ShortHash.shorthash(*args)
  end
end
