require 'ffi'
require_relative '../sodium/utils'
require_relative '../random_bytes'
require_relative '../sodium/buffer'
require_relative '../sodium/secret_buffer'
require_relative '../sodium/errors'

module Crypto
  module Box
    extend FFI::Library
    extend Sodium::Utils

    ffi_lib :libsodium

    attach_function :primitive,       :crypto_box_primitive,      [], :string
    attach_function :seedbytes,       :crypto_box_seedbytes,      [], :size_t
    attach_function :publickeybytes,  :crypto_box_publickeybytes, [], :size_t
    attach_function :secretkeybytes,  :crypto_box_secretkeybytes, [], :size_t
    attach_function :noncebytes,      :crypto_box_noncebytes,     [], :size_t
    attach_function :macbytes,        :crypto_box_macbytes,       [], :size_t

    PRIMITIVE       = primitive.freeze
    SEEDBYTES       = seedbytes.freeze
    PUBLICKEYBYTES  = publickeybytes.freeze
    SECRETKEYBYTES  = secretkeybytes.freeze
    NONCEBYTES      = noncebytes.freeze
    MACBYTES        = macbytes.freeze

    attach_function :crypto_box_keypair,      [:buffer_out, :buffer_out],             :int
    attach_function :crypto_box_seed_keypair, [:buffer_out, :buffer_out, :buffer_in], :int

    attach_function :crypto_box_easy,         [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in, :buffer_in], :int
    attach_function :crypto_box_open_easy,    [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in, :buffer_in], :int

    module_function

    def nonce
      RandomBytes.buf(NONCEBYTES)
    end

    def keypair
      public_key = Sodium::Buffer.new(:uchar, PUBLICKEYBYTES)
      public_key.primitive = PRIMITIVE
      secret_key = Sodium::Buffer.new(:uchar, SECRETKEYBYTES)
      secret_key.primitive = PRIMITIVE
      crypto_box_keypair(public_key, secret_key)

      [public_key, secret_key]
    end

    def seed_keypair(seed)
      check_length(seed, SEEDBYTES, :Seed)

      public_key = Sodium::Buffer.new(:uchar, PUBLICKEYBYTES)
      public_key.primitive = PRIMITIVE
      secret_key = Sodium::Buffer.new(:uchar, SECRETKEYBYTES)
      secret_key.primitive = PRIMITIVE
      seed.readonly if seed.is_a?(Sodium::SecretBuffer)
      crypto_box_seed_keypair(public_key, secret_key, seed)

      [public_key, secret_key]
    ensure
      seed.noaccess if seed.is_a?(Sodium::SecretBuffer)
    end

    def memory_locked_keypair
      public_key = Sodium::Buffer.new(:uchar, PUBLICKEYBYTES)
      public_key.primitive = PRIMITIVE
      secret_key = Sodium::SecretBuffer.new(SECRETKEYBYTES, PRIMITIVE)
      crypto_box_keypair(public_key, secret_key)
      secret_key.noaccess

      [public_key, secret_key]
    end

    def memory_locked_seed_keypair(seed)
      check_length(seed, SEEDBYTES, :Seed)

      public_key = Sodium::Buffer.new(:uchar, PUBLICKEYBYTES)
      public_key.primitive = PRIMITIVE
      secret_key = Sodium::SecretBuffer.new(SECRETKEYBYTES, PRIMITIVE)
      seed.readonly if seed.is_a?(Sodium::SecretBuffer)
      crypto_box_seed_keypair(public_key, secret_key, seed)
      secret_key.noaccess

      [public_key, secret_key]
    ensure
      seed.noaccess if seed.is_a?(Sodium::SecretBuffer)
    end

    def box(message, nonce, public_key, secret_key)
      message_len = get_size(message)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      ciphertext = Sodium::Buffer.new(:uchar, message_len + MACBYTES)
      ciphertext.primitive = PRIMITIVE
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      crypto_box_easy(ciphertext, message, message_len, nonce, public_key, secret_key)

      ciphertext
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end

    def open(ciphertext, nonce, public_key, secret_key)
      ciphertext_len = get_size(ciphertext)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      decrypted = Sodium::Buffer.new(:uchar, ciphertext_len - MACBYTES)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      unless crypto_box_open_easy(decrypted, ciphertext, ciphertext_len, nonce, public_key, secret_key).zero?
        raise Sodium::CryptoError, "Message forged", caller
      end

      decrypted
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end

    def easy_in_place(data, nonce, public_key, secret_key)
      message = get_string(data)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      message_len = get_size(message)
      message << zeros(MACBYTES)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      crypto_box_easy(message, message, message_len, nonce, public_key, secret_key)

      message
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end

    def open_easy_in_place(data, nonce, public_key, secret_key, utf8 = false)
      ciphertext = get_string(data)
      unless (message_len = get_size(ciphertext) - MACBYTES) > 0
        fail Sodium::LengthError, "Ciphertext is too short", caller
      end

      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      unless crypto_box_open_easy(ciphertext, ciphertext, get_size(ciphertext), nonce, public_key, secret_key).zero?
        raise Sodium::CryptoError, "Message forged", caller
      end

      if utf8
        ciphertext.slice!(message_len..-1).force_encoding(Encoding::UTF_8)
      else
        ciphertext.slice!(message_len..-1)
      end

      ciphertext
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end
  end

  module_function

  def box(*args)
    Box.box(*args)
  end
end
