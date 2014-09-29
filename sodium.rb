require 'ffi'

module Sodium
  class CryptoError < StandardError; end
  class LengthError < ArgumentError; end
  class MemoryError < StandardError; end

  extend FFI::Library
  ffi_lib :libsodium

  attach_function :init, :sodium_init, [], :int, blocking: true

  attach_function :memcmp,  :sodium_memcmp,   [:buffer_in, :buffer_in, :size_t],  :int
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
        fail NoMemoryError
      end
      mem
    end

    def allocarray(count, size)
      unless (mem = sodium_allocarray(count, size))
        fail NoMemoryError
      end
      mem
    end

    def noaccess(ptr)
      if sodium_mprotect_noaccess(ptr) == -1
        fail MemoryError
      end
    end

    def readonly(ptr)
      if sodium_mprotect_readonly(ptr) == -1
        fail MemoryError
      end
    end

    def readwrite(ptr)
      if sodium_mprotect_readwrite(ptr) == -1
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

      def zeros(n)
        zeros = "\0" * n
        zeros.force_encoding(Encoding::ASCII_8BIT)
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

    def_delegators :@random, :address, :to_i, :size

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

    def self.from_ptr(data, size)
      ptr = Utils.check_pointer(data)
      instance = allocate
      instance.instance_variable_set(:@size, size.to_int)
      instance.instance_variable_set(:@key, ptr)
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
      @size = nil
      remove_finalizer
      readwrite
      Sodium.free(@key)
      @key = nil
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

    attach_function :crypto_secretbox_keybytes,   [], :size_t
    attach_function :crypto_secretbox_noncebytes, [], :size_t
    attach_function :crypto_secretbox_macbytes,   [], :size_t

    KEYBYTES    = crypto_secretbox_keybytes
    NONCEBYTES  = crypto_secretbox_noncebytes
    MACBYTES    = crypto_secretbox_macbytes

    attach_function :crypto_secretbox_easy,       [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int, blocking: true
    attach_function :crypto_secretbox_open_easy,  [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int, blocking: true

    class << self
      def nonce
        Random.new(NONCEBYTES)
      end

      def key
        Random.new(KEYBYTES)
      end

      def memory_locked_key
        Key.new(KEYBYTES)
      end

      def easy(data, nonce, key)
        message = Utils.check_string(data)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(key, KEYBYTES, :Key)

        ciphertext_len = MACBYTES + message.bytesize
        ciphertext = FFI::MemoryPointer.new(:uchar, ciphertext_len)
        key.readonly if key.is_a?(Key)
        rc = crypto_secretbox_easy(ciphertext, message, message.bytesize, nonce, key)
        key.noaccess if key.is_a?(Key)
        if rc == -1
          fail CryptoError
        end

        ciphertext.read_bytes(ciphertext_len)
      end

      def easy_in_place(data, nonce, key)
        message = Utils.check_string(data)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(key, KEYBYTES, :Key)

        message_len = message.bytesize
        message << Utils.zeros(MACBYTES)
        key.readonly if key.is_a?(Key)
        rc = crypto_secretbox_easy(message, message, message_len, nonce, key)
        key.noaccess if key.is_a?(Key)
        if rc == -1
          fail CryptoError
        end

        message
      end

      def open_easy(data, nonce, key, utf8 = false)
        ciphertext = Utils.check_string(data)
        unless (message_len = ciphertext.bytesize - MACBYTES) > 0
          fail LengthError
        end

        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(key, KEYBYTES, :Key)

        decrypted = FFI::MemoryPointer.new(:uchar, message_len)
        key.readonly if key.is_a?(Key)
        rc = crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext.bytesize, nonce, key)
        key.noaccess if key.is_a?(Key)
        if rc == -1
          fail CryptoError
        end

        if utf8
          decrypted.read_bytes(message_len).force_encoding(Encoding::UTF_8)
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
      def nonce
        Random.new(NONCEBYTES)
      end

      def keypair
        public_key = FFI::MemoryPointer.new(:uchar, PUBLICKEYBYTES)
        secret_key = FFI::MemoryPointer.new(:uchar, SECRETKEYBYTES)
        if crypto_box_keypair(public_key, secret_key) == -1
          fail CryptoError
        end

        [public_key, secret_key]
      end

      def memory_locked_keypair
        public_key = FFI::MemoryPointer.new(:uchar, PUBLICKEYBYTES)
        secret_key = Sodium.malloc(SECRETKEYBYTES)
        if crypto_box_keypair(public_key, secret_key) == -1
          Sodium.free(secret_key)
          fail CryptoError
        end

        [public_key, Key.from_ptr(secret_key, SECRETKEYBYTES)]
      end

      def easy(data, nonce, public_key, secret_key)
        message = Utils.check_string(data)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(public_key, PUBLICKEYBYTES, :Public_Key)
        Utils.check_length(secret_key, SECRETKEYBYTES, :Secret_Key)

        ciphertext_len = MACBYTES + message.bytesize
        ciphertext = FFI::MemoryPointer.new(:uchar, ciphertext_len)
        secret_key.readonly if secret_key.is_a?(Key)
        rc = crypto_box_easy(ciphertext, message, message.bytesize, nonce, public_key, secret_key)
        secret_key.noaccess if secret_key.is_a?(Key)
        if rc == -1
          fail CryptoError
        end

        ciphertext.read_bytes(ciphertext_len)
      end

      def easy_in_place(data, nonce, public_key, secret_key)
        message = Utils.check_string(data)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(public_key, PUBLICKEYBYTES, :Public_Key)
        Utils.check_length(secret_key, SECRETKEYBYTES, :Secret_Key)

        message_len = message.bytesize
        message << Utils.zeros(MACBYTES)
        secret_key.readonly if secret_key.is_a?(Key)
        rc = crypto_box_easy(message, message, message_len, nonce, public_key, secret_key)
        secret_key.noaccess if secret_key.is_a?(Key)
        if rc == -1
          fail CryptoError
        end

        message
      end

      def open_easy(data, nonce, public_key, secret_key, utf8 = false)
        ciphertext = Utils.check_string(data)
        unless (message_len = ciphertext.bytesize - MACBYTES) > 0
          fail LengthError
        end

        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(public_key, PUBLICKEYBYTES, :Public_Key)
        Utils.check_length(secret_key, SECRETKEYBYTES, :Secret_Key)

        decrypted = FFI::MemoryPointer.new(:uchar, message_len)
        secret_key.readonly if secret_key.is_a?(Key)
        rc = crypto_box_open_easy(decrypted, ciphertext, ciphertext.bytesize, nonce, public_key, secret_key)
        secret_key.noaccess if secret_key.is_a?(Key)
        if rc == -1
          fail CryptoError
        end

        if utf8
          decrypted.read_bytes(message_len).force_encoding(Encoding::UTF_8)
        else
          decrypted.read_bytes(message_len)
        end
      end
    end
  end
end

module Sodium
  module Generichash
    extend FFI::Library
    ffi_lib :libsodium

    attach_function :crypto_generichash_bytes_min,      [], :size_t
    attach_function :crypto_generichash_bytes_max,      [], :size_t
    attach_function :crypto_generichash_bytes,          [], :size_t
    attach_function :crypto_generichash_keybytes_min,   [], :size_t
    attach_function :crypto_generichash_keybytes_max,   [], :size_t
    attach_function :crypto_generichash_keybytes,       [], :size_t

    BYTES_MIN     = crypto_generichash_bytes_min
    BYTES_MAX     = crypto_generichash_bytes_max
    BYTES         = crypto_generichash_bytes
    KEYBYTES_MIN  = crypto_generichash_keybytes_min
    KEYBYTES_MAX  = crypto_generichash_keybytes_max
    KEYBYTES      = crypto_generichash_keybytes

    attach_function :crypto_generichash,  [:buffer_out, :size_t, :buffer_in, :ulong_long, :buffer_in, :size_t], :int

    class State < FFI::Struct
      pack 64
      layout  :h,         [:uint64, 8],
              :t,         [:uint64, 2],
              :f,         [:uint64, 2],
              :buf,       [:uint64, 2 * 128],
              :buflen,    :size_t,
              :last_node, :uint8
    end

    attach_function :crypto_generichash_init,   [State.ptr, :buffer_in, :size_t, :size_t],  :int
    attach_function :crypto_generichash_update, [State.ptr, :buffer_in, :ulong_long],       :int
    attach_function :crypto_generichash_final,  [State.ptr, :buffer_out, :ulong_long],      :int

    class << self
      def hash(data, size = BYTES)
        message = Utils.check_string(data)
        if size > BYTES_MAX ||size < BYTES_MIN
          fail LengthError
        end

        hash = FFI::MemoryPointer.new(:uchar, size)
        if crypto_generichash(hash, size, message, message.bytesize, nil, 0) == -1
          fail CryptoError
        end

        hash.read_bytes(size)
      end

      def init(size = BYTES)
        if size > BYTES_MAX ||size < BYTES_MIN
          fail LengthError
        end

        state = State.new
        hash  = FFI::MemoryPointer.new(:uchar, size)
        if crypto_generichash_init(state, nil, 0, size) == -1
          fail CryptoError
        end

        [state, hash]
      end

      def update(state, data)
        Utils.check_pointer(state)
        message = Utils.check_string(data)

        if crypto_generichash_update(state, message, message.bytesize) == -1
          fail CryptoError
        end
      end

      def final(state, hash)
        Utils.check_pointer(state)
        Utils.check_pointer(hash)

        if crypto_generichash_final(state, hash, hash.size) == -1
          fail CryptoError
        end

        hash.read_bytes(hash.size)
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
          fail NoMemoryError
        end

        Key.from_ptr(out, outlen)
      end

      def str(data, opslimit = OPSLIMIT_INTERACTIVE, memlimit = MEMLIMIT_INTERACTIVE)
        passwd = Utils.check_string(data)

        hashed_password = FFI::MemoryPointer.new(:char, STRBYTES)
        if crypto_pwhash_scryptsalsa208sha256_str(hashed_password, passwd, passwd.bytesize, opslimit, memlimit) == -1
          fail NoMemoryError
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
