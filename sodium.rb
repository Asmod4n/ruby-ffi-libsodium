require 'ffi'

module Sodium
  extend FFI::Library
  ffi_lib :libsodium

  attach_function :init, :sodium_init, [], :int, blocking: true

  attach_function :memzero, :sodium_memzero,  [:pointer, :size_t],  :void,    blocking: true
  attach_function :free,    :sodium_free,     [:pointer],           :void,    blocking: true
  attach_function :sodium_mlock,              [:pointer, :size_t],  :int,     blocking: true
  attach_function :sodium_munlock,            [:pointer, :size_t],  :int,     blocking: true
  attach_function :sodium_malloc,             [:size_t],            :pointer, blocking: true
  attach_function :sodium_allocarray,         [:size_t, :size_t],   :pointer, blocking: true
  attach_function :sodium_mprotect_noaccess,  [:pointer],           :int,     blocking: true
  attach_function :sodium_mprotect_readonly,  [:pointer],           :int,     blocking: true
  attach_function :sodium_mprotect_readwrite, [:pointer],           :int,     blocking: true

  class << self
    def mlock(addr, len)
      if sodium_mlock(addr, len) == -1
        fail MemoryError
      end
    end

    def munlock(addr, len)
      if sodium_munlock(addr, len) == -1
        fail MemoryError
      end
    end

    def malloc(size)
      unless (mem = sodium_malloc(size))
        fail MemoryError
      end
      mem
    end

    def allocarray(count, size)
      unless (mem = sodium_allocarray(count, size))
        fail MemoryError
      end
      mem
    end

    def noaccess(ptr)
      if sodium_mprotect_noaccess(ptr) == -1
        free(ptr)
        fail MemoryError
      end
    end

    def readonly(ptr)
      if sodium_mprotect_readonly(ptr) == -1
        free(ptr)
        fail MemoryError
      end
    end

    def readwrite(ptr)
      if sodium_mprotect_readwrite(ptr) == -1
        free(ptr)
        fail MemoryError
      end
    end
  end
end

module Sodium
  module Randombytes
    extend FFI::Library
    ffi_lib :libsodium

    attach_function :random,  :randombytes_random,  [],                     :uint32,  blocking: true
    attach_function :uniform, :randombytes_uniform, [:uint32],              :uint32,  blocking: true
    attach_function :buf,     :randombytes_buf,     [:buffer_in, :size_t],  :void,    blocking: true
    attach_function :close,   :randombytes_close,   [],                     :int,     blocking: true
    attach_function :stir,    :randombytes_stir,    [],                     :void,    blocking: true
  end
end

module Sodium
  class CryptoError < StandardError; end
  class LengthError < ArgumentError; end
  class MemoryError < CryptoError; end
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
          if data.respond_to?(:size)
            unless data.size == length.to_int
              fail LengthError, "Expected a #{length} bytes #{description}, got #{data.size} bytes", caller
            end
          elsif data.respond_to?(:to_str)
            unless data.to_str.bytesize == length.to_int
              fail LengthError, "Expected a #{length} bytes #{description}, got #{data.to_str.bytesize} bytes", caller
            end
          else
            fail ArgumentError, "#{description} must be of type FFI::Pointer or String and be #{length.to_int} bytes long", caller
          end
        end
        true
      end

      def check_pointer(ptr)
        if ptr.is_a?(FFI::Pointer)
          ptr
        elsif ptr.respond_to?(:to_ptr)
          ptr.to_ptr
        else
          fail ArgumentError, "#{ptr.class} is not a FFI::Pointer", caller
        end
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
  class Random
    extend Forwardable

    def_delegators :@random, :address, :to_i

    attr_reader :size

    def initialize(size)
      @size = size.to_int
      @random = FFI::MemoryPointer.new(:uchar, @size)
      Randombytes.buf(@random, @size)
    end

    def to_ptr
      @random
    end

    def to_str
      @random.read_bytes(@size)
    end
  end
end

module Sodium
  class Key
    extend Forwardable

    def_delegators :@key, :address, :to_i

    attr_reader :size

    def self.from_passphrase(passphrase, size)
      passphrase_ptr = Utils.check_pointer(passphrase)
      instance = allocate
      instance.instance_variable_set(:@size, size.to_int)
      instance.instance_variable_set(:@key, passphrase_ptr)
      instance.noaccess
      instance.setup_finalizer
      instance
    end

    def initialize(size)
      @size = size.to_int
      @key = Sodium.malloc(@size)
      Randombytes.buf(@key, @size)
      noaccess
      setup_finalizer
    end

    def to_ptr
      @key
    end

    def to_str
      readonly
      str = @key.read_bytes(@size)
      noaccess
      str
    end

    def free
      remove_finalizer
      readwrite
      Sodium.free(@key)
    end

    def noaccess
      Sodium.noaccess(@key)
    end

    def readonly
      Sodium.readonly(@key)
    end

    def readwrite
      Sodium.readwrite(@key)
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
        Sodium.readwrite(key)
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

    attach_function :crypto_secretbox_easy,       [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int, blocking: true
    attach_function :crypto_secretbox_open_easy,  [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int, blocking: true

    class << self
      def nonce
        Random.new(NONCEBYTES)
      end

      def memory_locked_key
        Key.new(KEYBYTES)
      end

      def key
        Random.new(KEYBYTES)
      end

      def easy(data, nonce, key)
        message = Utils.check_string(data)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(key, KEYBYTES, :Key)

        key.readonly if key.is_a?(Key)

        ciphertext_len = MACBYTES + message.bytesize
        ciphertext = FFI::MemoryPointer.new(:uchar, ciphertext_len)
        if crypto_secretbox_easy(ciphertext, message, message.bytesize, nonce, key) == -1
          key.free if key.is_a?(Key)
          fail CryptoError
        else
          key.noaccess if key.is_a?(Key)
        end

        ciphertext.read_bytes(ciphertext_len)
      end

      def open_easy(data, nonce, key, utf8 = false)
        ciphertext = Utils.check_string(data)
        unless (message_len = ciphertext.bytesize - MACBYTES) > 0
          fail LengthError
        end

        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(key, KEYBYTES, :Key)

        key.readonly if key.is_a?(Key)

        decrypted = FFI::MemoryPointer.new(:uchar, message_len)
        if crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext.bytesize, nonce, key) == -1
          key.free if key.is_a?(Key)
          fail CryptoError
        else
          key.noaccess if key.is_a?(Key)
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
  module Box
    extend FFI::Library
    ffi_lib :libsodium

    attach_function :crypto_box_seedbytes,      [], :size_t
    attach_function :crypto_box_publickeybytes, [], :size_t
    attach_function :crypto_box_secretkeybytes, [], :size_t
    attach_function :crypto_box_noncebytes,     [], :size_t
    attach_function :crypto_box_macbytes,       [], :size_t

    SEEDBYTES       = crypto_box_seedbytes
    PUBLICKEYBYTES  = crypto_box_publickeybytes
    SECRETKEYBYTES  = crypto_box_secretkeybytes
    NONCEBYTES      = crypto_box_noncebytes
    MACBYTES        = crypto_box_macbytes

    attach_function :crypto_box_keypair,      [:buffer_out, :buffer_out],             :int, blocking: true
    attach_function :crypto_box_seed_keypair, [:buffer_out, :buffer_out, :buffer_in], :int, blocking: true
    attach_function :crypto_scalarmult_base,  [:buffer_out, :buffer_in],              :int, blocking: true

    attach_function :crypto_box_easy,       [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in, :buffer_in], :int, blocking: true
    attach_function :crypto_box_open_easy,  [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in, :buffer_in], :int, blocking: true

    class << self
      def easy(data, nonce, public_key, secret_key)
        message = Utils.check_string(data)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(public_key, PUBLICKEYBYTES, :Public_Key)
        Utils.check_length(secret_key, SECRETKEYBYTES, :Secret_Key)

        public_key.readonly if public_key.is_a?(Key)
        secret_key.readonly if secret_key.is_a?(Key)

        ciphertext_len = MACBYTES + message.bytesize
        ciphertext = FFI::MemoryPointer.new(:uchar, ciphertext_len)
        if easy(ciphertext, message, message.bytesize, nonce, public_key, secret_key) == -1
          public_key.free if public_key.is_a?(Key)
          secret_key.free if secret_key.is_a?(Key)
          fail CryptoError
        else
          public_key.noaccess if public_key.is_a?(Key)
          secret_key.noaccess if secret_key.is_a?(Key)
        end

        ciphertext.read_bytes(ciphertext_len)
      end

      def open_easy(data, nonce, public_key, secret_key, utf8 = false)
        ciphertext = Utils.check_string(ciphertext)
        unless (message_len = ciphertext.bytesize - MACBYTES) > 0
          fail LengthError
        end

        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(public_key, PUBLICKEYBYTES, :Public_Key)
        Utils.check_length(secret_key, SECRETKEYBYTES, :Secret_Key)

        public_key.readonly if public_key.is_a?(Key)
        secret_key.readonly if secret_key.is_a?(Key)

        decrypted = FFI::MemoryPointer.new(:uchar, message_len)
        if open_easy(decrypted, ciphertext, ciphertext.bytesize, nonce, public_key, secret_key) == -1
          public_key.free if public_key.is_a?(Key)
          secret_key.free if secret_key.is_a?(Key)
          fail CryptoError
        else
          public_key.noaccess if public_key.is_a?(Key)
          secret_key.noaccess if secret_key.is_a?(Key)
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
  module Pwhash_ScryptSalsa208sha256
    PACK_CHAR = 'c*'.freeze
    extend FFI::Library
    ffi_lib :libsodium

    attach_function :crypto_pwhash_scryptsalsa208sha256_saltbytes,            [], :size_t
    attach_function :crypto_pwhash_scryptsalsa208sha256_strbytes,             [], :size_t
    attach_function :crypto_pwhash_scryptsalsa208sha256_strprefix,            [], :string
    attach_function :crypto_pwhash_scryptsalsa208sha256_opslimit_interactive, [], :size_t
    attach_function :crypto_pwhash_scryptsalsa208sha256_memlimit_interactive, [], :size_t
    attach_function :crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive,   [], :size_t
    attach_function :crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive,   [], :size_t

    SALTBYTES             = crypto_pwhash_scryptsalsa208sha256_saltbytes
    STRBYTES              = crypto_pwhash_scryptsalsa208sha256_strbytes
    STRPREFIX             = crypto_pwhash_scryptsalsa208sha256_strprefix
    OPSLIMIT_INTERACTIVE  = crypto_pwhash_scryptsalsa208sha256_opslimit_interactive
    MEMLIMIT_INTERACTIVE  = crypto_pwhash_scryptsalsa208sha256_memlimit_interactive
    OPSLIMIT_SENSITIVE    = crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive
    MEMLIMIT_SENSITIVE    = crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive

    attach_function :crypto_pwhash_scryptsalsa208sha256,            [:buffer_out, :ulong_long, :buffer_in, :ulong_long, :buffer_in, :ulong_long, :size_t],  :int, blocking: true
    attach_function :crypto_pwhash_scryptsalsa208sha256_str,        [:buffer_out, :buffer_in, :ulong_long, :ulong_long, :size_t],                           :int, blocking: true
    attach_function :crypto_pwhash_scryptsalsa208sha256_str_verify, [:buffer_in, :buffer_in, :ulong_long],                                                  :int, blocking: true

    class << self
      def scrypt(data, outlen = Box::SEEDBYTES, salt = Random.new(SALTBYTES), opslimit = OPSLIMIT_INTERACTIVE, memlimit = MEMLIMIT_INTERACTIVE)
        passwd = Utils.check_string(data)
        Utils.check_length(salt, SALTBYTES, :Salt)

        out = Sodium.malloc(outlen)
        if crypto_pwhash_scryptsalsa208sha256(out, outlen, passwd, passwd.bytesize, salt, opslimit, memlimit) == -1
          Sodium.free(out)
          fail MemoryError
        end

        Key.from_passphrase(out, outlen)
      end

      def str(data, opslimit = OPSLIMIT_INTERACTIVE, memlimit = MEMLIMIT_INTERACTIVE)
        passwd = Utils.check_string(data)

        hashed_password = FFI::MemoryPointer.new(:char, STRBYTES)
        if crypto_pwhash_scryptsalsa208sha256_str(hashed_password, passwd, passwd.bytesize, opslimit, memlimit) == -1
          fail MemoryError
        end

        hashed_password.read_array_of_char(STRBYTES).pack(PACK_CHAR)
      end

      def str_verify(str, data)
        Utils.check_length(str, STRBYTES, :Str)
        passwd = Utils.check_string(data)

        crypto_pwhash_scryptsalsa208sha256_str_verify(str, passwd, passwd.bytesize) == 0
      end
    end
  end
end

Thread.exclusive do
  if Sodium.init == -1
    fail LoadError, 'Could not initialize sodium'
  end
end
