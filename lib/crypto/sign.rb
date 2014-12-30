require 'ffi'
require_relative '../sodium/utils'
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

    attach_function :crypto_sign_keypair,       [:buffer_out, :buffer_out],             :int
    attach_function :crypto_sign_seed_keypair,  [:buffer_out, :buffer_out, :buffer_in], :int

    attach_function :crypto_sign,       [:buffer_out, :pointer, :buffer_in, :ulong_long, :buffer_in],  :int
    attach_function :crypto_sign_open,  [:buffer_out, :pointer, :buffer_in, :ulong_long, :buffer_in],  :int

    attach_function :crypto_sign_detached,        [:buffer_out, :pointer, :buffer_in, :ulong_long, :buffer_in], :int
    attach_function :crypto_sign_verify_detached, [:buffer_in, :buffer_in, :ulong_long, :buffer_in],            :int

    module_function

    def keypair
      public_key = zeros(PUBLICKEYBYTES)
      secret_key = zeros(SECRETKEYBYTES)
      crypto_sign_keypair(public_key, secret_key)

      [public_key, secret_key]
    end

    def seed_keypair(seed)
      check_length(seed, SEEDBYTES, :Seed)

      public_key = zeros(PUBLICKEYBYTES)
      secret_key = zeros(SECRETKEYBYTES)
      seed.readonly if seed.is_a?(Sodium::SecretBuffer)
      crypto_sign_seed_keypair(public_key, secret_key, seed)

      [public_key, secret_key]
    ensure
      seed.noaccess if seed.is_a?(Sodium::SecretBuffer)
    end

    def memory_locked_keypair
      public_key = zeros(PUBLICKEYBYTES)
      secret_key = Sodium::SecretBuffer.new(SECRETKEYBYTES)
      crypto_sign_keypair(public_key, secret_key)
      secret_key.noaccess

      [public_key, secret_key]
    end

    def memory_locked_seed_keypair(seed)
      check_length(seed, SEEDBYTES, :Seed)

      public_key = zeros(PUBLICKEYBYTES)
      secret_key = Sodium::SecretBuffer.new(SECRETKEYBYTES)
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

      sealed_message = zeros(message_len + BYTES)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      crypto_sign(sealed_message, nil, message, message_len, secret_key)

      sealed_message
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end

    def open(sealed_message, public_key)
      sealed_message_len = get_size(sealed_message)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)

      unsealed_message = zeros(sealed_message_len - BYTES)
      unsealed_message_len = FFI::MemoryPointer.new(:ulong_long)
      if crypto_sign_open(unsealed_message, unsealed_message_len, sealed_message, sealed_message_len, public_key) == -1
        raise Sodium::CryptoError, "Incorrect signature", caller
      end

      unsealed_message
    end

    def detached(message, secret_key)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      signature = zeros(BYTES)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      crypto_sign_detached(signature, nil, message, get_size(message), secret_key)

      signature
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end

    def verify_detached(signature, message, public_key)
      check_length(signature, BYTES, :Signature)

      crypto_sign_verify_detached(signature, message, get_size(message), public_key) == 0
    end
  end

  Sign.freeze

  module_function

  def sign(*args)
    Sign.sign(*args)
  end
end
