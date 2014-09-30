require 'ffi'

module Sodium
  class CryptoError < StandardError; end
  class LengthError < ArgumentError; end
  class MemoryError < StandardError; end

  extend FFI::Library
  ffi_lib :libsodium

  attach_function :init,  :sodium_init, [], :int,  blocking: true

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
        fail NoMemoryError, "Failed to allocate memory size=#{size} bytes"
      end
      mem
    end

    def allocarray(count, size)
      unless (mem = sodium_allocarray(count, size))
        fail NoMemoryError, "Failed to allocate memory size=#{count * size} bytes"
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
  module Utils
    class << self
      def check_length(data, length, description)
        if data.is_a?(String) ||data.respond_to?(:bytesize)
          unless data.bytesize == length.to_int
            fail LengthError, "Expected a #{length} bytes #{description}, got #{data.bytesize} bytes", caller
          end
        elsif data.is_a?(FFI::Pointer) ||data.respond_to?(:size)
          unless data.size == length.to_int
            fail LengthError, "Expected a #{length} bytes #{description}, got #{data.size} bytes", caller
          end
        else
          fail ArgumentError, "#{description} must be of type String or FFI::Pointer and be #{length.to_int} bytes long", caller
        end
        true
      end

      def get_pointer(ptr)
        if ptr.is_a?(FFI::Pointer)
          ptr
        elsif ptr.respond_to?(:to_ptr)
          ptr.to_ptr
        else
          fail ArgumentError, "#{ptr.class} is not a FFI::Pointer", caller
        end
      end

      def get_string(string)
        if string.is_a?(String)
          string
        elsif string.respond_to?(:to_str)
          string.to_str
        elsif string.respond_to?(:read_string)
          string.read_string
        else
          fail ArgumentError, "#{string.class} is not a String", caller
        end
      end

      def get_size(data)
        if data.is_a?(String) ||data.respond_to?(:bytesize)
          data.bytesize
        elsif data.is_a?(FFI::Pointer) ||data.respond_to?(:size)
          data.size
        else
          fail ArgumentError, "#{data.class} doesn't respond to :bytesize or :size", caller
        end
      end

      ZERO = ("\0".force_encoding(Encoding::ASCII_8BIT)).freeze

      def zeros(n)
        ZERO * n
      end
    end
  end
end

module Sodium
  module Randombytes
    extend FFI::Library
    ffi_lib :libsodium

    attach_function :randombytes_buf, [:buffer_out, :size_t], :void,  blocking: true

    attach_function :random,  :randombytes_random,  [],         :uint32,  blocking: true
    attach_function :uniform, :randombytes_uniform, [:uint32],  :uint32,  blocking: true
    attach_function :close,   :randombytes_close,   [],         :int,     blocking: true
    attach_function :stir,    :randombytes_stir,    [],         :void,    blocking: true

    def self.buf(size)
      buffer = FFI::MemoryPointer.new(:uchar, size)
      randombytes_buf(buffer, size)
      buffer.read_bytes(size)
    end
  end
end

module Sodium
  class SecretKey
    extend Forwardable

    def_delegators :@key, :address, :to_i

    attr_reader :size

    def self.from_ptr(data, size)
      ptr = Utils.get_pointer(data)
      instance = allocate
      instance.instance_variable_set(:@size, size.to_int)
      instance.instance_variable_set(:@key, ptr)
      instance.noaccess
      instance.setup_finalizer
      instance
    end

    def initialize(size)
      @size = size.to_int
      @key = Sodium.malloc(size)
      Randombytes.randombytes_buf(@key, size)
      noaccess
      setup_finalizer
    end

    def to_ptr
      @key
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

    attach_function :primitive, :crypto_secretbox_primitive,  [], :string

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
        Randombytes.buf(NONCEBYTES)
      end

      def easy(message, nonce, key)
        message_len = Utils.get_size(message)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(key, KEYBYTES, :SecretKey)

        ciphertext = FFI::MemoryPointer.new(:uchar, MACBYTES + message_len)
        key.readonly if key.is_a?(SecretKey)
        rc = crypto_secretbox_easy(ciphertext, message, message_len, nonce, key)
        key.noaccess if key.is_a?(SecretKey)
        if rc == -1
          fail CryptoError
        end

        ciphertext.read_bytes(ciphertext.size)
      end

      def easy_in_place(data, nonce, key)
        message = Utils.get_string(data)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(key, KEYBYTES, :SecretKey)

        message_len = message.bytesize
        message << Utils.zeros(MACBYTES)
        key.readonly if key.is_a?(SecretKey)
        rc = crypto_secretbox_easy(message, message, message_len, nonce, key)
        key.noaccess if key.is_a?(SecretKey)
        if rc == -1
          fail CryptoError
        end

        message
      end

      def open_easy(ciphertext, nonce, key)
        ciphertext_len = Utils.get_size(ciphertext)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(key, KEYBYTES, :SecretKey)

        decrypted = FFI::MemoryPointer.new(:uchar, ciphertext_len - MACBYTES)
        key.readonly if key.is_a?(SecretKey)
        rc = crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, key)
        key.noaccess if key.is_a?(SecretKey)
        if rc == -1
          fail CryptoError
        end

        decrypted.read_bytes(decrypted.size)
      end

      def open_easy_in_place(data, nonce, key, utf8 = false)
        ciphertext = Utils.get_string(data)
        unless (message_len = ciphertext.bytesize - MACBYTES) > 0
          fail LengthError
        end

        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(key, KEYBYTES, :SecretKey)

        key.readonly if key.is_a?(SecretKey)
        rc = crypto_secretbox_open_easy(ciphertext, ciphertext, ciphertext.bytesize, nonce, key)
        key.noaccess if key.is_a?(SecretKey)
        if rc == -1
          fail CryptoError
        end

        if utf8
          ciphertext.slice!(message_len..-1).force_encoding(Encoding::UTF_8)
        else
          ciphertext.slice!(message_len..-1)
        end

        ciphertext
      end
    end
  end
end

module Sodium
  module Auth
    extend FFI::Library
    ffi_lib :libsodium

    attach_function :primitive, :crypto_auth_primitive, [], :string

    attach_function :crypto_auth_bytes,     [], :size_t
    attach_function :crypto_auth_keybytes,  [], :size_t

    BYTES     = crypto_auth_bytes
    KEYBYTES  = crypto_auth_keybytes

    attach_function :crypto_auth,         [:buffer_out, :buffer_in, :ulong_long, :buffer_in], :int, blocking: true
    attach_function :crypto_auth_verify,  [:buffer_in, :buffer_in, :ulong_long, :buffer_in],  :int, blocking: true

    class << self
      def auth(message, key)
        message_len = Utils.get_size(message)
        Utils.check_length(key, KEYBYTES, :SecretKey)

        mac = FFI::MemoryPointer.new(:uchar, BYTES)
        key.readonly if key.is_a?(SecretKey)
        rc = crypto_auth(mac, message, message_len, key)
        key.noaccess if key.is_a?(SecretKey)
        if rc == -1
          fail CryptoError
        end

        mac.read_bytes(BYTES)
      end

      def verify(mac, message, key)
        Utils.check_length(mac, BYTES, :Mac)
        message_len = Utils.get_size(message)
        Utils.check_length(key, KEYBYTES, :SecretKey)

        key.readonly if key.is_a?(SecretKey)
        rc = crypto_auth_verify(mac, message, message_len, key)
        key.noaccess if key.is_a?(SecretKey)

        rc == 0
      end
    end
  end

  def self.auth(*args)
    Auth.auth(*args)
  end
end

module Sodium
  module Box
    extend FFI::Library
    ffi_lib :libsodium

    attach_function :primitive, :crypto_box_primitive,  [], :string

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
        Randombytes.buf(NONCEBYTES)
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

        [public_key, SecretKey.from_ptr(secret_key, SECRETKEYBYTES)]
      end

      def public_key_from(secret_key)
        Utils.check_length(secret_key, SECRETKEYBYTES, :SecretKey)

        public_key = FFI::MemoryPointer.new(:uchar, PUBLICKEYBYTES)
        secret_key.readonly if secret_key.is_a?(SecretKey)
        rc = crypto_scalarmult_base(public_key, secret_key)
        secret_key.noaccess if secret_key.is_a?(SecretKey)
        if rc == -1
          fail CryptoError
        end

        public_key
      end

      def easy(message, nonce, public_key, secret_key)
        message_len = Utils.get_size(message)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(public_key, PUBLICKEYBYTES, :PublicKey)
        Utils.check_length(secret_key, SECRETKEYBYTES, :SecretKey)

        ciphertext = FFI::MemoryPointer.new(:uchar, MACBYTES + message_len)
        secret_key.readonly if secret_key.is_a?(SecretKey)
        rc = crypto_box_easy(ciphertext, message, message_len, nonce, public_key, secret_key)
        secret_key.noaccess if secret_key.is_a?(SecretKey)
        if rc == -1
          fail CryptoError
        end

        ciphertext.read_bytes(ciphertext.size)
      end

      def easy_in_place(data, nonce, public_key, secret_key)
        message = Utils.get_string(data)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(public_key, PUBLICKEYBYTES, :PublicKey)
        Utils.check_length(secret_key, SECRETKEYBYTES, :SecretKey)

        message_len = message.bytesize
        message << Utils.zeros(MACBYTES)
        secret_key.readonly if secret_key.is_a?(SecretKey)
        rc = crypto_box_easy(message, message, message_len, nonce, public_key, secret_key)
        secret_key.noaccess if secret_key.is_a?(SecretKey)
        if rc == -1
          fail CryptoError
        end

        message
      end

      def open_easy(ciphertext, nonce, public_key, secret_key)
        ciphertext_len = Utils.get_size(ciphertext)
        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(public_key, PUBLICKEYBYTES, :PublicKey)
        Utils.check_length(secret_key, SECRETKEYBYTES, :SecretKey)

        decrypted = FFI::MemoryPointer.new(:uchar, ciphertext_len - MACBYTES)
        secret_key.readonly if secret_key.is_a?(SecretKey)
        rc = crypto_box_open_easy(decrypted, ciphertext, ciphertext_len, nonce, public_key, secret_key)
        secret_key.noaccess if secret_key.is_a?(SecretKey)
        if rc == -1
          fail CryptoError
        end

        decrypted.read_bytes(decrypted.size)
      end

      def open_easy_in_place(data, nonce, public_key, secret_key, utf8 = false)
        ciphertext = Utils.get_string(data)
        unless (message_len = ciphertext.bytesize - MACBYTES) > 0
          fail LengthError
        end

        Utils.check_length(nonce, NONCEBYTES, :Nonce)
        Utils.check_length(public_key, PUBLICKEYBYTES, :PublicKey)
        Utils.check_length(secret_key, SECRETKEYBYTES, :SecretKey)

        secret_key.readonly if secret_key.is_a?(SecretKey)
        rc = crypto_box_open_easy(ciphertext, ciphertext, ciphertext.bytesize, nonce, public_key, secret_key)
        secret_key.noaccess if secret_key.is_a?(SecretKey)
        if rc == -1
          fail CryptoError
        end

        if utf8
          ciphertext.slice!(message_len..-1).force_encoding(Encoding::UTF_8)
        else
          ciphertext.slice!(message_len..-1)
        end

        ciphertext
      end
    end
  end
end

module Sodium
  module Generichash
    extend FFI::Library
    ffi_lib :libsodium

    attach_function :primitive, :crypto_generichash_primitive,  [], :string

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

    attach_function :crypto_generichash,  [:buffer_out, :size_t, :buffer_in, :ulong_long, :buffer_in, :size_t], :int, blocking: true

    class State < FFI::Struct
      pack 64
      layout  :h,         [:uint64, 8],
              :t,         [:uint64, 2],
              :f,         [:uint64, 2],
              :buf,       [:uint8, 2 * 128],
              :buflen,    :size_t,
              :last_node, :uint8
    end

    attach_function :crypto_generichash_init,   [State.ptr, :buffer_in, :size_t, :size_t],  :int, blocking: true
    attach_function :crypto_generichash_update, [State.ptr, :buffer_in, :ulong_long],       :int, blocking: true
    attach_function :crypto_generichash_final,  [State.ptr, :buffer_out, :ulong_long],      :int, blocking: true

    class << self
      def generichash(message, hash_size = BYTES, key = nil)
        message_len = Utils.get_size(message)
        if hash_size > BYTES_MAX ||hash_size < BYTES_MIN
          fail LengthError
        end

        if key
          key_len = Utils.get_size(key)

          if key_len > KEYBYTES_MAX ||key_len < KEYBYTES_MIN
            fail LengthError
          end
        else
          key_len = 0
        end

        blake2b = FFI::MemoryPointer.new(:uchar, hash_size)
        if crypto_generichash(blake2b, hash_size, message, message_len, key, key_len) == -1
          fail CryptoError
        end

        blake2b.read_bytes(hash_size)
      end

      def init(key = nil, hash_size = BYTES)
        if key
          key_len = Utils.get_size(key)

          if key_len > KEYBYTES_MAX ||key_len < KEYBYTES_MIN
            fail LengthError
          end
        else
          key_len = 0
        end

        if hash_size > BYTES_MAX ||hash_size < BYTES_MIN
          fail LengthError
        end

        state = State.new
        blake2b = FFI::MemoryPointer.new(:uchar, hash_size)
        if crypto_generichash_init(state, key, key_len, hash_size) == -1
          fail CryptoError
        end

        [state, blake2b]
      end

      def update(state, message)
        Utils.get_pointer(state)
        message_len = Utils.get_size(message)

        if crypto_generichash_update(state, message, message_len) == -1
          fail CryptoError
        end
      end

      def final(state, blake2b)
        Utils.get_pointer(state)
        Utils.get_pointer(blake2b)

        if crypto_generichash_final(state, blake2b, blake2b.size) == -1
          fail CryptoError
        end

        blake2b.read_bytes(blake2b.size)
      end
    end
  end

  def self.generichash(*args)
    Generichash.generichash(*args)
  end
end

module Sodium
  module Pwhash
    module ScryptSalsa208SHA256
      PACK_C = 'c*'.freeze
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
        def salt
          Randombytes.buf(SALTBYTES)
        end

        def scryptsalsa208sha256(passwd, outlen, salt, opslimit = OPSLIMIT_INTERACTIVE, memlimit = MEMLIMIT_INTERACTIVE)
          passwd_len = Utils.get_size(passwd)
          Utils.check_length(salt, SALTBYTES, :Salt)

          out = Sodium.malloc(outlen)
          if crypto_pwhash_scryptsalsa208sha256(out, outlen, passwd, passwd_len, salt, opslimit, memlimit) == -1
            Sodium.free(out)
            fail NoMemoryError
          end

          SecretKey.from_ptr(out, outlen)
        end

        def str(passwd, opslimit = OPSLIMIT_INTERACTIVE, memlimit = MEMLIMIT_INTERACTIVE)
          passwd_len = Utils.get_size(passwd)

          hashed_password = FFI::MemoryPointer.new(:char, STRBYTES)
          if crypto_pwhash_scryptsalsa208sha256_str(hashed_password, passwd, passwd_len, opslimit, memlimit) == -1
            fail NoMemoryError
          end

          hashed_password.read_array_of_char(STRBYTES).pack(PACK_C)
        end

        def str_verify(str, passwd)
          Utils.check_length(str, STRBYTES, :Str)
          passwd_len = Utils.get_size(passwd)

          crypto_pwhash_scryptsalsa208sha256_str_verify(str, passwd, passwd_len) == 0
        end
      end
    end

    def self.scryptsalsa208sha256(*args)
      ScryptSalsa208SHA256.scryptsalsa208sha256(*args)
    end
  end
end

Thread.exclusive do
  if Sodium.init == -1
    fail LoadError, 'Could not initialize sodium'
  end
end
