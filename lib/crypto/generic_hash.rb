require 'ffi'
require_relative '../sodium/utils'
require_relative '../sodium/secret_buffer'
require_relative '../sodium/errors'

module Crypto
  module GenericHash
    extend FFI::Library
    extend Sodium::Utils

    ffi_lib :libsodium

    attach_function :primitive,     :crypto_generichash_primitive,    [], :string
    attach_function :bytes_min,     :crypto_generichash_bytes_min,    [], :size_t
    attach_function :bytes_max,     :crypto_generichash_bytes_max,    [], :size_t
    attach_function :bytes,         :crypto_generichash_bytes,        [], :size_t
    attach_function :keybytes_min,  :crypto_generichash_keybytes_min, [], :size_t
    attach_function :keybytes_max,  :crypto_generichash_keybytes_max, [], :size_t
    attach_function :keybytes,      :crypto_generichash_keybytes,     [], :size_t

    PRIMITIVE     = primitive.freeze
    BYTES_MIN     = bytes_min.freeze
    BYTES_MAX     = bytes_max.freeze
    BYTES         = bytes.freeze
    KEYBYTES_MIN  = keybytes_min.freeze
    KEYBYTES_MAX  = keybytes_max.freeze
    KEYBYTES      = keybytes.freeze

    attach_function :crypto_generichash,  [:buffer_out, :size_t, :buffer_in, :ulong_long, :buffer_in, :size_t], :int

    class State < FFI::Struct
      pack 64
      layout  :h,         [:uint64, 8],
              :t,         [:uint64, 2],
              :f,         [:uint64, 2],
              :buf,       [:uint8, 2 * 128],
              :buflen,    :size_t,
              :last_node, :uint8
    end

    attach_function :crypto_generichash_init,   [State.ptr, :buffer_in, :size_t, :size_t],  :int
    attach_function :crypto_generichash_update, [State.ptr, :buffer_in, :ulong_long],       :int
    attach_function :crypto_generichash_final,  [State.ptr, :buffer_out, :ulong_long],      :int

    module_function

    def generichash(message, hash_size = BYTES, key = nil)
      if key
        key_len = get_size(key)
      else
        key_len = 0
      end

      blake2b = zeros(hash_size)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      if crypto_generichash(blake2b, hash_size, message, get_size(message), key, key_len) == -1
        raise Sodium::CryptoError
      end

      blake2b
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def init(key = nil, hash_size = BYTES)
      if key
        key_len = get_size(key)
      else
        key_len = 0
      end

      state = State.new
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      if crypto_generichash_init(state, key, key_len, hash_size) == -1
        raise Sodium::CryptoError
      end

      [state, zeros(hash_size)]
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def update(state, message)
      crypto_generichash_update(state, message, get_size(message))
    end

    def final(state, blake2b)
      if crypto_generichash_final(state, blake2b, blake2b.bytesize) == -1
        raise Sodium::CryptoError
      end

      blake2b
    end
  end

  GenericHash.freeze

  module_function

  def generichash(*args)
    GenericHash.generichash(*args)
  end
end
