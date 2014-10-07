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

    attach_function :crypto_secretbox_easy,       [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int, blocking: true
    attach_function :crypto_secretbox_open_easy,  [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int, blocking: true

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
      key.noaccess if key.is_a?(Sodium::SecretBuffer)

      ciphertext
    end

    def open(ciphertext, nonce, key)
      ciphertext_len = get_size(ciphertext)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      decrypted = Sodium::Buffer.new(:uchar, ciphertext_len - MACBYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      rc = crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, key)
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
      if rc == -1
        raise Sodium::CryptoError, "Message forged", caller
      end

      decrypted
    end

    def easy_in_place(data, nonce, key)
      message = get_string(data)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      message_len = message.bytesize
      message << zeros(MACBYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_secretbox_easy(message, message, message_len, nonce, key)
      key.noaccess if key.is_a?(Sodium::SecretBuffer)

      message
    end

    def open_easy_in_place(data, nonce, key, utf8 = false)
      ciphertext = get_string(data)
      unless (message_len = ciphertext.bytesize - MACBYTES) > 0
        fail Sodium::LengthError, "Ciphertext is too short", caller
      end

      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      key.readonly if key.is_a?(Sodium::SecretBuffer)
      rc = crypto_secretbox_open_easy(ciphertext, ciphertext, ciphertext.bytesize, nonce, key)
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
      if rc == -1
        raise Sodium::CryptoError, "Message forged", caller
      end

      if utf8
        ciphertext.slice!(message_len..-1).force_encoding(Encoding::UTF_8)
      else
        ciphertext.slice!(message_len..-1)
      end

      ciphertext
    end
  end

  module_function

  def secretbox(*args)
    SecretBox.secretbox(*args)
  end
end
