require 'ffi'
require_relative '../sodium/utils'
require_relative '../random_bytes'
require_relative '../sodium/buffer'
require_relative '../sodium/secret_buffer'
require_relative '../sodium'

module Crypto
  module SecretBox
    extend FFI::Library
    extend Sodium::Utils

    ffi_lib :libsodium

    attach_function :primitive,   :crypto_secretbox_primitive,  [], :string
    attach_function :keybytes,    :crypto_secretbox_keybytes,   [], :size_t
    attach_function :noncebytes,  :crypto_secretbox_noncebytes, [], :size_t
    attach_function :macbytes,    :crypto_secretbox_macbytes,   [], :size_t

    PRIMITIVE   = primitive.freeze
    KEYBYTES    = keybytes.freeze
    NONCEBYTES  = noncebytes.freeze
    MACBYTES    = macbytes.freeze

    attach_function :crypto_secretbox_easy,       [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int
    attach_function :crypto_secretbox_open_easy,  [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int

    module_function

    def nonce
      RandomBytes.buf(NONCEBYTES)
    end

    def secretbox(message, nonce, key)
      message_len = get_size(message)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      ciphertext = Sodium::Buffer.new(:uchar, message_len + MACBYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_secretbox_easy(ciphertext, message, message_len, nonce, key)

      ciphertext
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def open(ciphertext, nonce, key)
      ciphertext_len = get_size(ciphertext)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      decrypted = Sodium::Buffer.new(:uchar, ciphertext_len - MACBYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      if crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, key) == 0
        decrypted
      else
        raise Sodium::CryptoError, "Message forged", caller
      end
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def easy_in_place(data, nonce, key)
      message = String(data)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      message_len = message.bytesize
      message << zeros(MACBYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_secretbox_easy(message, message, message_len, nonce, key)

      message
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def open_easy_in_place(data, nonce, key, encoding = nil)
      ciphertext = String(data)
      ciphertext_len = ciphertext.bytesize
      if (message_len = ciphertext_len - MACBYTES) > 0
        check_length(nonce, NONCEBYTES, :Nonce)
        check_length(key, KEYBYTES, :SecretKey)

        key.readonly if key.is_a?(Sodium::SecretBuffer)
        if crypto_secretbox_open_easy(ciphertext, ciphertext, ciphertext_len, nonce, key) == 0
          if encoding
            ciphertext.slice!(message_len..-1).force_encoding(encoding)
          else
            ciphertext.slice!(message_len..-1)
          end

          ciphertext
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

  SecretBox.freeze

  module_function

  def secretbox(*args)
    SecretBox.secretbox(*args)
  end
end
