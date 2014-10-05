﻿require_relative '../../sodium'
require_relative '../../sodium/utils'
require_relative '../../sodium/secret_buffer'
require_relative '../../random_bytes'

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

      attach_function :crypto_aead_chacha20poly1305_encrypt,  [:buffer_out, :buffer_out, :buffer_in, :ulong_long, :buffer_in, :ulong_long, :pointer, :buffer_in, :buffer_in], :int, blocking: true
      attach_function :crypto_aead_chacha20poly1305_decrypt,  [:buffer_out, :buffer_out, :pointer, :buffer_in, :ulong_long, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int, blocking: true

      module_function

      def nonce
        RandomBytes.buf(NPUBBYTES)
      end

      def encrypt(message, additional_data, nonce, key)
        message_len = get_size(message)
        additional_data_len = get_size(additional_data)
        check_length(nonce, NPUBBYTES, :Nonce)
        check_length(key, KEYBYTES, :SecretKey)

        ciphertext = FFI::MemoryPointer.new(:uchar, message_len + ABYTES)
        ciphertext_len = FFI::MemoryPointer.new(:ulong_long)
        key.readonly if key.is_a?(Sodium::SecretBuffer)
        crypto_aead_chacha20poly1305_encrypt(ciphertext, ciphertext_len, message, message_len, additional_data, additional_data_len, nil, nonce, key)
        key.noaccess if key.is_a?(Sodium::SecretBuffer)

        [ciphertext, ciphertext_len.read_ulong_long]
      end

      def decrypt(ciphertext, clen, additional_data, nonce, key)
        ciphertext_len = get_int(clen)
        additional_data_len = get_size(additional_data)
        check_length(nonce, NPUBBYTES, :Nonce)
        check_length(key, KEYBYTES, :SecretKey)

        decrypted = FFI::MemoryPointer.new(:uchar, ciphertext_len)
        decrypted_len = FFI::MemoryPointer.new(:ulong_long)
        key.readonly if key.is_a?(Sodium::SecretBuffer)
        rc = crypto_aead_chacha20poly1305_decrypt(decrypted, decrypted_len, nil, ciphertext, ciphertext_len, additional_data, additional_data_len, nonce, key)
        key.noaccess if key.is_a?(Sodium::SecretBuffer)
        if rc == -1
          raise Sodium::CryptoError, "Message forged", caller
        end

        [decrypted, decrypted_len.read_ulong_long]
      end
    end
  end
end
