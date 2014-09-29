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
  class Nonce
    extend Forwardable

    def_delegators :@nonce, :address, :to_i

    attr_reader :size

    def initialize(size)
      @size = size.to_int
      @nonce = FFI::MemoryPointer.new(:uchar, @size)
      Randombytes.buf(@nonce, @size)
    end

    def to_ptr
      @nonce
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

    attach_function :easy,      :crypto_secretbox_easy,       [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int, blocking: true
    attach_function :open_easy, :crypto_secretbox_open_easy,  [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int, blocking: true

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

        if easy(ciphertext, message, message.bytesize, nonce, key) == -1
          key.free if key.is_a?(Key)
          fail CryptoError
        end

        ciphertext.read_bytes(ciphertext_len)
      end

      def decrypt(data, nonce, key, utf8 = false)
        ciphertext = Utils.check_string(data)
        unless (message_len = ciphertext.bytesize - MACBYTES) > 0
          fail LengthError
        end

        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(key, KEYBYTES, :Key)

        decrypted = FFI::MemoryPointer.new(:uchar, message_len)

        if open_easy(decrypted, ciphertext, ciphertext.bytesize, nonce, key) == -1
          key.free if key.is_a?(Key)
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
  module Box
    extend FFI::Library
    ffi_lib :libsodium

    attach_function :seedbytes,       :crypto_box_seedbytes,      [], :size_t
    attach_function :publickeybytes,  :crypto_box_publickeybytes, [], :size_t
    attach_function :secretkeybytes,  :crypto_box_secretkeybytes, [], :size_t
    attach_function :noncebytes,      :crypto_box_noncebytes,     [], :size_t
    attach_function :macbytes,        :crypto_box_macbytes,       [], :size_t

    SEEDBYTES       = seedbytes
    PUBLICKEYBYTES  = publickeybytes
    SECRETKEYBYTES  = secretkeybytes
    NONCEBYTES      = noncebytes
    MACBYTES        = macbytes

    attach_function :keypair,         :crypto_box_keypair,      [:buffer_out, :buffer_out],             :int, blocking: true
    attach_function :seed_keypair,    :crypto_box_seed_keypair, [:buffer_out, :buffer_out, :buffer_in], :int, blocking: true
    attach_function :scalarmult_base, :crypto_scalarmult_base,  [:buffer_out, :buffer_in],              :int, blocking: true

    attach_function :easy,      :crypto_box_easy,       [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in, :buffer_in], :int, blocking: true
    attach_function :open_easy, :crypto_box_open_easy,  [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in, :buffer_in], :int, blocking: true

    class << self
      def generate_keypair
        public_key = FFI::MemoryPointer.new(:uchar, PUBLICKEYBYTES)
        secret_key = FFI::MemoryPointer.new(:uchar, SECRETKEYBYTES)
        if keypair(public_key, secret_key) == -1
          fail CryptoError
        end
        [public_key, secret_key]
      end

      def public_key_from(secret_key)
        Utils.check_length(secret_key, SECRETKEYBYTES, :Secret_Key)

        public_key = FFI::MemoryPointer.new(:uchar, PUBLICKEYBYTES)
        if scalarmult_base(public_key, secret_key) == -1
          fail CryptoError
        end

        public_key
      end

      def encrypt(data, nonce, public_key, secret_key)
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
        end

        public_key.noaccess if public_key.is_a?(Key)
        secret_key.noaccess if secret_key.is_a?(Key)

        ciphertext.read_bytes(ciphertext_len)
      end

      def decrypt(data, nonce, public_key, secret_key, utf8 = false)
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
        end

        public_key.noaccess if public_key.is_a?(Key)
        secret_key.noaccess if secret_key.is_a?(Key)

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

    attach_function :saltbytes,             :crypto_pwhash_scryptsalsa208sha256_saltbytes,            [], :size_t
    attach_function :strbytes,              :crypto_pwhash_scryptsalsa208sha256_strbytes,             [], :size_t
    attach_function :strprefix,             :crypto_pwhash_scryptsalsa208sha256_strprefix,            [], :string
    attach_function :opslimit_interactive,  :crypto_pwhash_scryptsalsa208sha256_opslimit_interactive, [], :size_t
    attach_function :memlimit_interactive,  :crypto_pwhash_scryptsalsa208sha256_memlimit_interactive, [], :size_t
    attach_function :opslimit_sensitive,    :crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive,   [], :size_t
    attach_function :memlimit_sensitive,    :crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive,   [], :size_t

    SALTBYTES             = saltbytes
    STRBYTES              = strbytes
    STRPREFIX             = strprefix
    OPSLIMIT_INTERACTIVE  = opslimit_interactive
    MEMLIMIT_INTERACTIVE  = memlimit_interactive
    OPSLIMIT_SENSITIVE    = opslimit_sensitive
    MEMLIMIT_SENSITIVE    = memlimit_sensitive

    attach_function :scryptsalsa208sha256,            :crypto_pwhash_scryptsalsa208sha256,            [:buffer_out, :ulong_long, :buffer_in, :ulong_long, :buffer_in, :ulong_long, :size_t],  :int, blocking: true
    attach_function :scryptsalsa208sha256_str,        :crypto_pwhash_scryptsalsa208sha256_str,        [:buffer_out, :buffer_in, :ulong_long, :ulong_long, :size_t],                           :int, blocking: true
    attach_function :scryptsalsa208sha256_str_verify, :crypto_pwhash_scryptsalsa208sha256_str_verify, [:buffer_in, :buffer_in, :ulong_long],                                                  :int, blocking: true

    class << self
      def scrypt(data, outlen = Box::SEEDBYTES, salt = Nonce.new(SALTBYTES), opslimit = OPSLIMIT_INTERACTIVE, memlimit = MEMLIMIT_INTERACTIVE)
        passwd = Utils.check_string(data)
        Utils.check_length(salt, SALTBYTES, :Salt)

        out = Sodium.malloc(outlen)
        if scryptsalsa208sha256(out, outlen, passwd, passwd.bytesize, salt, opslimit, memlimit) == -1
          Sodium.free(out)
          fail MemoryError
        end

        Key.from_passphrase(out, outlen)
      end

      def str(data, opslimit = OPSLIMIT_INTERACTIVE, memlimit = MEMLIMIT_INTERACTIVE)
        passwd = Utils.check_string(data)

        hashed_password = FFI::MemoryPointer.new(:char, STRBYTES)
        if scryptsalsa208sha256_str(hashed_password, passwd, passwd.bytesize, opslimit, memlimit) == -1
          fail MemoryError
        end

        hashed_password.read_array_of_char(STRBYTES).pack(PACK_CHAR)
      end

      def str_verify(str, data)
        Utils.check_length(str, STRBYTES, :Str)
        passwd = Utils.check_string(data)

        scryptsalsa208sha256_str_verify(str, passwd, passwd.bytesize) == 0
      end
    end
  end
end

Thread.exclusive do
  if Sodium.init == -1
    fail LoadError, 'Could not initialize sodium'
  end
end
