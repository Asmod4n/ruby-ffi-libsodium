﻿require 'ffi'
require_relative '../sodium/utils'
require_relative '../random_bytes'
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
    attach_function :beforenmbytes,   :crypto_box_beforenmbytes,  [], :size_t

    PRIMITIVE       = primitive.freeze
    SEEDBYTES       = seedbytes.freeze
    PUBLICKEYBYTES  = publickeybytes.freeze
    SECRETKEYBYTES  = secretkeybytes.freeze
    NONCEBYTES      = noncebytes.freeze
    MACBYTES        = macbytes.freeze
    BEFORENMBYTES   = beforenmbytes.freeze

    attach_function :crypto_box_keypair,        [:buffer_out, :buffer_out],             :int
    attach_function :crypto_box_seed_keypair,   [:buffer_out, :buffer_out, :buffer_in], :int

    attach_function :crypto_box_beforenm,       [:buffer_out, :buffer_in, :buffer_in],  :int

    attach_function :crypto_box_easy,           [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in, :buffer_in], :int
    attach_function :crypto_box_open_easy,      [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in, :buffer_in], :int

    attach_function :crypto_box_detached,       [:buffer_out, :buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in, :buffer_in],  :int
    attach_function :crypto_box_open_detached,  [:buffer_out, :buffer_in, :buffer_in, :ulong_long, :buffer_in, :buffer_in, :buffer_in],   :int

    module_function

    def nonce
      RandomBytes.buf(NONCEBYTES)
    end

    def keypair
      public_key = zeros(PUBLICKEYBYTES)
      secret_key = zeros(SECRETKEYBYTES)
      crypto_box_keypair(public_key, secret_key)

      [public_key, secret_key]
    end

    def seed_keypair(seed)
      check_length(seed, SEEDBYTES, :Seed)

      public_key = zeros(PUBLICKEYBYTES)
      secret_key = zeros(SECRETKEYBYTES)
      seed.readonly if seed.is_a?(Sodium::SecretBuffer)
      crypto_box_seed_keypair(public_key, secret_key, seed)

      [public_key, secret_key]
    ensure
      seed.noaccess if seed.is_a?(Sodium::SecretBuffer)
    end

    def memory_locked_keypair
      public_key = zeros(PUBLICKEYBYTES)
      secret_key = Sodium::SecretBuffer.new(SECRETKEYBYTES)
      crypto_box_keypair(public_key, secret_key)
      secret_key.noaccess

      [public_key, secret_key]
    end

    def memory_locked_seed_keypair(seed)
      check_length(seed, SEEDBYTES, :Seed)

      public_key = zeros(PUBLICKEYBYTES)
      secret_key = Sodium::SecretBuffer.new(SECRETKEYBYTES)
      seed.readonly if seed.is_a?(Sodium::SecretBuffer)
      crypto_box_seed_keypair(public_key, secret_key, seed)
      secret_key.noaccess

      [public_key, secret_key]
    ensure
      seed.noaccess if seed.is_a?(Sodium::SecretBuffer)
    end

    def beforenm(public_key, secret_key)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      shared_secret = Sodium::SecretBuffer.new(BEFORENMBYTES)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      crypto_box_beforenm(shared_secret, public_key, secret_key)
      shared_secret.noaccess

      shared_secret
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end

    def box(message, nonce, public_key, secret_key)
      message_len = get_size(message)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      ciphertext = zeros(message_len + MACBYTES)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      crypto_box_easy(ciphertext, message, message_len, nonce, public_key, secret_key)

      ciphertext
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end

    def open(ciphertext, nonce, public_key, secret_key, encoding = nil)
      ciphertext_len = get_size(ciphertext)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      message = zeros(ciphertext_len - MACBYTES)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      if crypto_box_open_easy(message, ciphertext, ciphertext_len, nonce, public_key, secret_key) == -1
        raise Sodium::CryptoError, "Message forged", caller
      end

      if encoding
        message.force_encoding(encoding)
      end

      message
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end

    def box!(data, nonce, public_key, secret_key)
      message = String(data)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      message_len = message.bytesize
      message << zeros(MACBYTES)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      crypto_box_easy(message, message, message_len, nonce, public_key, secret_key)

      message
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end

    def open!(data, nonce, public_key, secret_key, encoding = nil)
      ciphertext = String(data)
      ciphertext_len = ciphertext.bytesize
      if (message_len = ciphertext_len - MACBYTES) < 0
        fail Sodium::LengthError, "Ciphertext is too short", caller
      end

      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      if crypto_box_open_easy(ciphertext, ciphertext, ciphertext_len, nonce, public_key, secret_key) == -1
        raise Sodium::CryptoError, "Message forged", caller
      end
      ciphertext.slice!(message_len..-1)

      if encoding
        ciphertext.force_encoding(encoding)
      end

      ciphertext
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end

    def detached(message, nonce, public_key, secret_key)
      message_len = get_size(message)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      ciphertext = zeros(message_len)
      mac = zeros(MACBYTES)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      crypto_box_detached(ciphertext, mac, message, message_len, nonce, public_key, secret_key)
      [ciphertext, mac]
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end

    def open_detached(ciphertext, mac, nonce, public_key, secret_key, encoding = nil)
      ciphertext_len = get_size(ciphertext)
      check_length(mac, MACBYTES, :Mac)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      message = zeros(ciphertext_len)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      if crypto_box_open_detached(message, ciphertext, mac, ciphertext_len, nonce, public_key, secret_key) == -1
        raise Sodium::CryptoError, "Message forged", caller
      end

      if encoding
        message.force_encoding(encoding)
      end

      message
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end

    def detached!(message, nonce, public_key, secret_key)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      mac = zeros(MACBYTES)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      crypto_box_detached(message, mac, message, get_size(message), nonce, public_key, secret_key)
      [message, mac]
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end

    def open_detached!(ciphertext, mac, nonce, public_key, secret_key, encoding = nil)
      check_length(mac, MACBYTES, :Mac)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      if crypto_box_open_detached(ciphertext, ciphertext, mac, get_size(ciphertext), nonce, public_key, secret_key) == -1
        raise Sodium::CryptoError, "Message forged", caller
      end

      if encoding && ciphertext.respond_to?(:force_encoding)
        ciphertext.force_encoding(encoding)
      end

      ciphertext
    ensure
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
    end
  end

  Box.freeze

  module_function

  def box(*args)
    Box.box(*args)
  end

  def box!(*args)
    Box.box!(*args)
  end
end
