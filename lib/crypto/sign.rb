require 'ffi'
require_relative '../sodium/utils'
require_relative '../sodium/buffer'
require_relative '../sodium/secret_buffer'
require_relative '../sodium'

module Crypto
  module Sign
    extend FFI::Library
    extend Sodium::Utils

    ffi_lib :libsodium

    attach_function :primitive,       :crypto_sign_primitive,       [], :string
    attach_function :bytes,           :crypto_sign_bytes,           [], :size_t
    attach_function :seedbytes,       :crypto_sign_seedbytes,       [], :size_t
    attach_function :publickeybytes,  :crypto_sign_publickeybytes,  [], :size_t
    attach_function :secretkeybytes,  :crypto_sign_secretkeybytes,  [], :size_t

    PRIMITIVE       = primitive.freeze
    BYTES           = bytes.freeze
    SEEDBYTES       = seedbytes.freeze
    PUBLICKEYBYTES  = publickeybytes.freeze
    SECRETKEYBYTES  = secretkeybytes.freeze

    attach_function :crypto_sign_keypair,       [:buffer_out, :buffer_out],             :int, blocking: true
    attach_function :crypto_sign_seed_keypair,  [:buffer_out, :buffer_out, :buffer_in], :int, blocking: true

    attach_function :crypto_sign,       [:buffer_out, :buffer_out, :buffer_in, :ulong_long, :buffer_in],  :int, blocking: true
    attach_function :crypto_sign_open,  [:buffer_out, :buffer_out, :buffer_in, :ulong_long, :buffer_in],  :int, blocking: true

    module_function

    def keypair
      public_key = Sodium::Buffer.new(:uchar, PUBLICKEYBYTES)
      public_key.primitive = PRIMITIVE
      secret_key = Sodium::Buffer.new(:uchar, SECRETKEYBYTES)
      secret_key.primitive = PRIMITIVE
      crypto_sign_keypair(public_key, secret_key)

      [public_key, secret_key]
    end

    def seed_keypair(seed)
      check_length(seed, SEEDBYTES, :Seed)

      public_key = Sodium::Buffer.new(:uchar, PUBLICKEYBYTES)
      public_key.primitive = PRIMITIVE
      secret_key = Sodium::Buffer.new(:uchar, SECRETKEYBYTES)
      secret_key.primitive = PRIMITIVE
      seed.readonly if seed.is_a?(Sodium::SecretBuffer)
      crypto_sign_seed_keypair(public_key, secret_key, seed)

      [public_key, secret_key]
    ensure
      seed.noaccess if seed.is_a?(Sodium::SecretBuffer)
    end

    def memory_locked_keypair
      public_key = Sodium::Buffer.new(:uchar, PUBLICKEYBYTES)
      public_key.primitive = PRIMITIVE
      secret_key = Sodium::SecretBuffer.new(SECRETKEYBYTES, PRIMITIVE)
      crypto_sign_keypair(public_key, secret_key)
      secret_key.noaccess

      [public_key, secret_key]
    end

    def memory_locked_seed_keypair(seed)
      check_length(seed, SEEDBYTES, :Seed)

      public_key = Sodium::Buffer.new(:uchar, PUBLICKEYBYTES)
      public_key.primitive = PRIMITIVE
      secret_key = Sodium::SecretBuffer.new(SECRETKEYBYTES, PRIMITIVE)
      seed.readonly if seed.is_a?(Sodium::SecretBuffer)
      crypto_sign_seed_keypair(public_key, secret_key, seed)
      secret_key.noaccess

      [public_key, secret_key]
    ensure
      seed.noaccess if seed.is_a?(Sodium::SecretBuffer)
    end

    def sign(message, secret_key)
      message_len = get_size(message)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      sealed_message = Sodium::Buffer.new(:uchar, message_len + BYTES)
      sealed_message.primitive = PRIMITIVE
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      crypto_sign(sealed_message, nil, message, message_len, secret_key)

      sealed_message
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end

    def open(sealed_message, public_key)
      sealed_message_len = get_size(sealed_message)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)

      unsealed_message = Sodium::Buffer.new(:uchar, sealed_message_len - BYTES)
      unsealed_message_len = FFI::MemoryPointer.new(:ulong_long)
      unless crypto_sign_open(unsealed_message, unsealed_message_len, sealed_message, sealed_message_len, public_key).zero?
        raise Sodium::CryptoError, "Incorrect signature", caller
      end

      unsealed_message
    end
  end

  module_function

  def sign(*args)
    Sign.sign(*args)
  end
end
