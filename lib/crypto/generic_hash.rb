require_relative '../sodium'
require_relative '../sodium/utils'
require_relative '../sodium/buffer'
require_relative '../sodium/secret_buffer'

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

    attach_function :crypto_generichash,  [:buffer_out, :size_t, :buffer_in, :ulong_long, :buffer_in, :size_t], :int, blocking: true

    class State < FFI::Struct
      pack 64
      layout  :h,         [:uint64, 8],
              :t,         [:uint64, 2],
              :f,         [:uint64, 2],
              :buf,       [:uint8, 2 * 128],
              :buflen,    :size_t,
              :last_node, :uint8
    end

    attach_function :crypto_generichash_init,   [State.ptr, :buffer_in, :size_t, :size_t],  :int, blocking: true
    attach_function :crypto_generichash_update, [State.ptr, :buffer_in, :ulong_long],       :int, blocking: true
    attach_function :crypto_generichash_final,  [State.ptr, :buffer_out, :ulong_long],      :int, blocking: true

    module_function

    def generichash(message, hash_size = BYTES, key = nil)
      message_len = get_size(message)
      if hash_size > BYTES_MAX ||hash_size < BYTES_MIN
        fail Sodium::LengthError, "Hash size must be between #{BYTES_MIN} and #{BYTES_MAX} bytes, got size=#{hash_size.to_int} bytes", caller
      end

      if key
        key_len = get_size(key)

        if key_len > KEYBYTES_MAX ||key_len < KEYBYTES_MIN
          fail Sodium::LengthError, "Key length must be between #{KEYBYTES_MIN} and #{KEYBYTES_MAX} bytes, got length=#{key_len} bytes", caller
        end
      else
        key_len = 0
      end

      blake2b = Sodium::Buffer.new(:uchar, hash_size)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      rc = crypto_generichash(blake2b, hash_size, message, message_len, key, key_len)
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
      if rc == -1
        raise Sodium::CryptoError
      end

      blake2b
    end

    def init(key = nil, hash_size = BYTES)
      if key
        key_len = get_size(key)

        if key_len > KEYBYTES_MAX ||key_len < KEYBYTES_MIN
          fail Sodium::LengthError, "Key length must be between #{KEYBYTES_MIN} and #{KEYBYTES_MAX} bytes, got length=#{key_len} bytes", caller
        end
      else
        key_len = 0
      end

      if hash_size > BYTES_MAX ||hash_size < BYTES_MIN
        fail Sodium::LengthError, "Hash size must be between #{BYTES_MIN} and #{BYTES_MAX} bytes, got size=#{hash_size.to_int} bytes", caller
      end

      state = State.new
      blake2b = Sodium::Buffer.new(:uchar, hash_size)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      rc = crypto_generichash_init(state, key, key_len, hash_size)
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
      if rc == -1
        raise Sodium::CryptoError
      end

      [state, blake2b]
    end

    def update(state, message)
      message_len = get_size(message)

      if crypto_generichash_update(state, message, message_len) == -1
        raise Sodium::CryptoError
      end
    end

    def final(state, blake2b)
      get_pointer(blake2b)

      if crypto_generichash_final(state, blake2b, blake2b.size) == -1
        raise Sodium::CryptoError
      end

      blake2b
    end
  end

  module_function

  def generichash(*args)
    GenericHash.generichash(*args)
  end
end
