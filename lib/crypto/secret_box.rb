require 'ffi'
require_relative '../sodium/utils'
require_relative '../random_bytes'
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

    attach_function :crypto_secretbox_detached,       [:buffer_out, :buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int
    attach_function :crypto_secretbox_open_detached,  [:buffer_out, :buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int

    module_function

    def nonce
      RandomBytes.buf(NONCEBYTES)
    end

    def secretbox(message, nonce, key)
      message_len = get_size(message)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      ciphertext = zeros(message_len + MACBYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_secretbox_easy(ciphertext, message, message_len, nonce, key)

      ciphertext
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def open(ciphertext, nonce, key, encoding = nil)
      ciphertext_len = get_size(ciphertext)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      decrypted = zeros(ciphertext_len - MACBYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      if crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, key) == -1
        raise Sodium::CryptoError, "Message forged", caller
      end

      if encoding
        decrypted.force_encoding(encoding)
      end

      decrypted
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def secretbox!(data, nonce, key)
      message = String(data)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      message_len = message.bytesize
      message << zeros(MACBYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_secretbox_easy(message, message, message_len, nonce, key)

      message.force_encoding(Encoding::ASCII_8BIT)
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def open!(data, nonce, key, encoding = nil)
      ciphertext = String(data)

      if (message_len = (ciphertext_len = ciphertext.bytesize) - MACBYTES) < 0
        fail Sodium::LengthError, "Ciphertext is too short", caller
      end

      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      key.readonly if key.is_a?(Sodium::SecretBuffer)
      if crypto_secretbox_open_easy(ciphertext, ciphertext, ciphertext_len, nonce, key) == -1
        raise Sodium::CryptoError, "Message forged", caller
      end

      ciphertext.slice!(message_len..-1)
      if encoding
        ciphertext.force_encoding(encoding)
      end

      ciphertext
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def detached(message, nonce, key)
      message_len = get_size(message)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      ciphertext = zeros(message_len)
      mac = zeros(MACBYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_secretbox_easy(ciphertext, mac, message, message_len, nonce, key)

      [ciphertext, mac]
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def open_detached(ciphertext, mac, nonce, key, encoding = nil)
      ciphertext_len = get_size(ciphertext)
      check_length(mac, MACBYTES, :Mac)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      decrypted = zeros(ciphertext_len)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      if crypto_secretbox_open_easy(decrypted, ciphertext, mac, ciphertext_len, nonce, key) == -1
        raise Sodium::CryptoError, "Message forged", caller
      end

      if encoding
        decrypted.force_encoding(encoding)
      end

      decrypted
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def detached!(message, nonce, key)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      mac = zeros(MACBYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_secretbox_easy(message, message, mac, get_size(message), nonce, key)

      [message, mac]
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end

    def open_detached!(ciphertext, mac, nonce, key, encoding = nil)
      check_length(mac, MACBYTES, :Mac)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      key.readonly if key.is_a?(Sodium::SecretBuffer)
      if crypto_secretbox_open_easy(ciphertext, ciphertext, mac, get_size(ciphertext), nonce, key) == -1
        raise Sodium::CryptoError, "Message forged", caller
      end

      if encoding && ciphertext.respond_to?(:force_encoding)
        ciphertext.force_encoding(encoding)
      end

      ciphertext
    ensure
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
    end
  end

  SecretBox.freeze

  module_function

  def secretbox(*args)
    SecretBox.secretbox(*args)
  end

  def secretbox!(*args)
    SecretBox.secretbox!(*args)
  end
end
