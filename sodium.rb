require 'ffi'

module Sodium
  extend FFI::Library
  ffi_lib :libsodium

  attach_function :init, :sodium_init, [], :int

  attach_function :memzero,             :sodium_memzero,            [:pointer, :size_t],  :void
  attach_function :mlock,               :sodium_mlock,              [:pointer, :size_t],  :int
  attach_function :munlock,             :sodium_munlock,            [:pointer, :size_t],  :int
  attach_function :malloc,              :sodium_malloc,             [:size_t],            :pointer
  attach_function :allocarray,          :sodium_allocarray,         [:size_t, :size_t],   :pointer
  attach_function :free,                :sodium_free,               [:pointer],           :void
  attach_function :mprotect_noaccess,   :sodium_mprotect_noaccess,  [:pointer],           :int
  attach_function :mprotect_readonly,   :sodium_mprotect_readonly,  [:pointer],           :int
  attach_function :mprotect_readwrite,  :sodium_mprotect_readwrite, [:pointer],           :int
end

module Sodium
  module Randombytes
    extend FFI::Library
    ffi_lib :libsodium

    attach_function :random,  :randombytes_random,  [],                     :uint32
    attach_function :uniform, :randombytes_uniform, [:uint32],              :uint32
    attach_function :buf,     :randombytes_buf,     [:buffer_in, :size_t],  :void
    attach_function :close,   :randombytes_close,   [],                     :int
    attach_function :stir,    :randombytes_stir,    [],                     :void
  end
end

module Sodium
  class CryptoError < StandardError; end
  class LengthError < ArgumentError; end
  class MessageError < CryptoError; end
end

module Sodium
  module Utils
    class << self
      def check_length(data, length, description)
        case data
        when FFI::Pointer
          unless data.size == length.to_int
            fail LengthError, "Expected a #{length} bytes #{description}, got #{data.size} bytes", caller
          end
        when String
          unless data.bytesize == length.to_int
            fail LengthError, "Expected a #{length} bytes #{description}, got #{data.bytesize} bytes", caller
          end
        else
          if data.respond_to(:to_ptr)
            unless data.to_ptr.size == length.to_int
              fail LengthError, "Expected a #{length} bytes #{description}, got #{data.to_ptr.size} bytes", caller
            end
          elsif data.respond_to?(:to_str)
            unless data.to_str.bytesize == length.to_int
              fail LengthError, "Expected a #{length} bytes #{description}, got #{data.to_str.bytesize} bytes", caller
            end
          else
            fail ArgumentError, "#{description} must be of type String or FFI::Pointer and be #{length.to_int} bytes long", caller
          end
        end
        true
      end

      def check_string(string)
        if string.is_a?(String)
          string
        elsif string.respond_to?(:to_str)
          string.to_str
        else
          fail ArgumentError, "#{string.class} is not a String", caller
        end
      end
    end
  end
end

module Sodium
  class Nonce
    extend Forwardable

    def_delegators :@nonce, :address, :to_i

    def initialize(size)
      @size = size.to_int
      @nonce = FFI::MemoryPointer.new(:uchar, @size)
      Randombytes.buf(@nonce, @size)
    end

    def to_ptr
      @nonce
    end

    def to_str
      @nonce.read_bytes(@size)
    end
  end
end

module Sodium
  class Key
    extend Forwardable

    def_delegators :@key, :address, :to_i

    attr_reader :size

    def initialize(size)
      @size = size.to_int
      @key = Sodium.malloc(@size)
      Randombytes.buf(@key, @size)
      setup_finalizer
      noaccess
    end

    def to_ptr
      @key
    end

    def to_str
      readonly
      @key.read_bytes(@size)
      noaccess
    end

    def free
      remove_finalizer
      Sodium.free(@key)
    end

    def noaccess
      unless Sodium.mprotect_noaccess(@key) == 0
        fail 'foo'
      end
    end

    def readonly
      unless Sodium.mprotect_readonly(@key) == 0
        fail 'foo'
      end
    end

    def readwrite
      unless Sodium.mprotect_readwrite(@key) == 0
        fail 'foo'
      end
    end

    def setup_finalizer
      ObjectSpace.define_finalizer(self, self.class.free(@key))
    end

    private

    def remove_finalizer
      ObjectSpace.undefine_finalizer self
    end

    def self.free(key)
      ->(obj_id) do
        Sodium.free(key)
        true
      end
    end
  end
end

module Sodium
  module SecretBox
    extend FFI::Library
    ffi_lib :libsodium

    attach_function :keybytes,    :crypto_secretbox_keybytes,   [], :size_t
    attach_function :noncebytes,  :crypto_secretbox_noncebytes, [], :size_t
    attach_function :macbytes,    :crypto_secretbox_macbytes,   [], :size_t

    KEYBYTES    = keybytes
    NONCEBYTES  = noncebytes
    MACBYTES    = macbytes

    attach_function :easy,      :crypto_secretbox_easy,       [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int
    attach_function :open_easy, :crypto_secretbox_open_easy,  [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int

    class << self
      def generate_nonce
        Nonce.new(NONCEBYTES)
      end

      def generate_key
        Key.new(KEYBYTES)
      end

      def encrypt(data, nonce, key)
        message = Utils.check_string(data)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(key, KEYBYTES, :Key)

        ciphertext_len = MACBYTES + message.bytesize
        ciphertext = FFI::MemoryPointer.new(:uchar, ciphertext_len)

        key.readonly if key.is_a?(Key)
        rc = easy(ciphertext, message, message.bytesize, nonce, key)
        key.noaccess if key.is_a?(Key)
        unless rc == 0
          fail CryptoError
        end

        ciphertext.read_bytes(ciphertext_len)
      end

      def decrypt(data, nonce, key, utf8 = false)
        ciphertext = Utils.check_string(data)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(key, KEYBYTES, :Key)

        unless (message_len = ciphertext.bytesize - MACBYTES) > 0
          fail LengthError
        end
        decrypted = FFI::MemoryPointer.new(:uchar, message_len)

        key.readonly if key.is_a?(Key)
        rc = open_easy(decrypted, ciphertext, ciphertext.bytesize, nonce, key)
        key.noaccess if key.is_a?(Key)
        unless rc == 0
          fail CryptoError
        end

        if utf8
          str = decrypted.read_bytes(message_len)
          str.force_encoding(Encoding::UTF_8)
          str
        else
          decrypted.read_bytes(message_len)
        end
      end
    end
  end
end

module Sodium
  module Auth
    extend FFI::Library
    ffi_lib :libsodium

    attach_function :bytes,     :crypto_auth_bytes,     [], :size_t
    attach_function :keybytes,  :crypto_auth_keybytes,  [], :size_t

    BYTES     = bytes
    KEYBYTES  = keybytes

    attach_function :auth,    :crypto_auth,         [:buffer_out, :buffer_in, :ulong_long, :buffer_in], :int
    attach_function :verify,  :crypto_auth_verify,  [:buffer_in, :buffer_in, :ulong_long, :buffer_in],  :int
  end
end

module Sodium
  module Box
    extend FFI::Library
    ffi_lib :libsodium

    attach_function :publickeybytes,  :crypto_box_publickeybytes, [], :size_t
    attach_function :secretkeybytes,  :crypto_box_secretkeybytes, [], :size_t
    attach_function :noncebytes,      :crypto_box_noncebytes,     [], :size_t
    attach_function :macbytes,        :crypto_box_macbytes,       [], :size_t

    PUBLICKEYBYTES  = publickeybytes
    SECRETKEYBYTES  = secretkeybytes
    NONCEBYTES      = noncebytes
    MACBYTES        = macbytes

    attach_function :keypair,         :crypto_box_keypair,      [:buffer_out, :buffer_out],             :int
    attach_function :seed_keypair,    :crypto_box_seed_keypair, [:buffer_out, :buffer_out, :buffer_in], :int
    attach_function :scalarmult_base, :crypto_scalarmult_base,  [:buffer_out, :buffer_in],              :int

    attach_function :easy,      :crypto_box_easy,       [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in, :buffer_in], :int
    attach_function :open_easy, :crypto_box_open_easy,  [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in, :buffer_in], :int

    class << self
      def generate_keypair
        public_key = FFI::MemoryPointer.new(:uchar, PUBLICKEYBYTES)
        secret_key = FFI::MemoryPointer.new(:uchar, SECRETKEYBYTES)
        unless keypair(public_key, secret_key) == 0
          fail CryptoError
        end
        [public_key, secret_key]
      end

      def public_key_from(secret_key)
        Utils.check_length(secret_key, SECRETKEYBYTES, :Secret_Key)
        public_key = FFI::MemoryPointer.new(:uchar, PUBLICKEYBYTES)
        unless scalarmult_base(public_key, secret_key) == 0
          fail CryptoError
        end
        public_key
      end

      def encrypt(data, nonce, public_key, secret_key)
        message = Utils.check_string(data)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(public_key, PUBLICKEYBYTES, :Public_Key)
        Utils.check_length(secret_key, SECRETKEYBYTES, :Secret_Key)


        ciphertext_len = MACBYTES + message.bytesize
        ciphertext = FFI::MemoryPointer.new(:uchar, ciphertext_len)

        unless easy(ciphertext, message, message.bytesize, nonce, public_key, secret_key) == 0
          fail CryptoError
        end

        ciphertext.read_bytes(ciphertext_len)
      end

      def decrypt(data, nonce, public_key, secret_key, utf8 = false)
        ciphertext = Utils.check_string(ciphertext)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(public_key, PUBLICKEYBYTES, :Public_Key)
        Utils.check_length(secret_key, SECRETKEYBYTES, :Secret_Key)

        unless (message_len = ciphertext.bytesize - MACBYTES) > 0
          fail LengthError
        end
        decrypted = FFI::MemoryPointer.new(:uchar, message_len)

        unless open_easy(decrypted, ciphertext, ciphertext.bytesize, nonce, public_key, secret_key) == 0
          fail MessageError
        end

        if utf8
          str = decrypted.read_bytes(message_len)
          str.force_encoding(Encoding::UTF_8)
          str
        else
          decrypted.read_bytes(message_len)
        end
      end
    end
  end
end

Thread.exclusive do
  if Sodium.init == -1
    fail LoadError, 'Could not initialize sodium'
  end
end
