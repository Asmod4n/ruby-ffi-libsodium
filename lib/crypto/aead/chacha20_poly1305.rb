﻿require 'ffi'
require_relative '../../sodium/utils'
require_relative '../../random_bytes'
require_relative '../../sodium/secret_buffer'
require_relative '../../sodium/errors'

module Crypto
  module AEAD
    module Chacha20Poly1305
      PRIMITIVE = 'chacha20poly1305'.freeze

      extend FFI::Library
      extend Sodium::Utils

      ffi_lib :libsodium

      class << self
        def crypto_aead_chacha20poly1305_primitive
          PRIMITIVE
        end

        alias_method :primitive, :crypto_aead_chacha20poly1305_primitive
      end

      attach_function :keybytes,  :crypto_aead_chacha20poly1305_keybytes,   [], :size_t
      attach_function :npubbytes, :crypto_aead_chacha20poly1305_npubbytes,  [], :size_t
      attach_function :abytes,    :crypto_aead_chacha20poly1305_abytes,     [], :size_t

      KEYBYTES  = keybytes.freeze
      NPUBBYTES = npubbytes.freeze
      ABYTES    = abytes.freeze

      attach_function :crypto_aead_chacha20poly1305_encrypt,  [:buffer_out, :pointer, :buffer_in, :ulong_long, :buffer_in, :ulong_long, :pointer, :buffer_in, :buffer_in], :int
      attach_function :crypto_aead_chacha20poly1305_decrypt,  [:buffer_out, :pointer, :pointer, :buffer_in, :ulong_long, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int

      module_function

      def nonce
        RandomBytes.buf(NPUBBYTES)
      end

      def encrypt(message, additional_data, nonce, key)
        message_len = get_size(message)
        check_length(nonce, NPUBBYTES, :Nonce)
        check_length(key, KEYBYTES, :SecretKey)

        ciphertext = zeros(message_len + ABYTES)
        key.readonly if key.is_a?(Sodium::SecretBuffer)
        crypto_aead_chacha20poly1305_encrypt(ciphertext, nil, message, message_len, additional_data, get_size(additional_data), nil, nonce, key)

        ciphertext
      ensure
        key.noaccess if key.is_a?(Sodium::SecretBuffer)
      end

      def decrypt(ciphertext, additional_data, nonce, key, encoding = nil)
        ciphertext_len = get_size(ciphertext)
        if (decrypted_len = ciphertext_len - ABYTES) >= 0
          check_length(nonce, NPUBBYTES, :Nonce)
          check_length(key, KEYBYTES, :SecretKey)

          decrypted = zeros(decrypted_len)
          key.readonly if key.is_a?(Sodium::SecretBuffer)
          if crypto_aead_chacha20poly1305_decrypt(decrypted, nil, nil, ciphertext, ciphertext_len, additional_data, get_size(additional_data), nonce, key) == 0
            if encoding
              decrypted.force_encoding(encoding)
            else
              decrypted
            end
          else
            raise Sodium::CryptoError, "Message forged", caller
          end
        else
          fail Sodium::LengthError, "Ciphertext is too short", caller
        end
      ensure
        key.noaccess if key.is_a?(Sodium::SecretBuffer)
      end
    end

    Chacha20Poly1305.freeze
  end

  AEAD.freeze
end
