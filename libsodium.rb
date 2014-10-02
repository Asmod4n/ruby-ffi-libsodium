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

  module_function

  def mlock(addr, len)
    if sodium_mlock(addr, len) == -1
      fail MemoryError, "Could not lock length=#{len.to_int} bytes memory at address=#{addr.address}", caller
    end
  end

  def munlock(addr, len)
    if sodium_munlock(addr, len) == -1
      fail MemoryError, "Could not unlock length=#{len.to_int} bytes memory at address=#{addr.address}", caller
    end
  end

  def malloc(size)
    unless (mem = sodium_malloc(size))
      fail NoMemoryError, "Failed to allocate memory size=#{size.to_int} bytes", caller
    end
    mem
  end

  def allocarray(count, size)
    unless (mem = sodium_allocarray(count, size))
      fail NoMemoryError, "Failed to allocate memory size=#{count.to_int * size.to_int} bytes", caller
    end
    mem
  end

  def noaccess(ptr)
    if sodium_mprotect_noaccess(ptr) == -1
      fail MemoryError, "Memory at address=#{ptr.address} is not secured with #{self}.malloc", caller
    end
  end

  def readonly(ptr)
    if sodium_mprotect_readonly(ptr) == -1
      fail MemoryError, "Memory at address=#{ptr.address} is not secured with #{self}.malloc", caller
    end
  end

  def readwrite(ptr)
    if sodium_mprotect_readwrite(ptr) == -1
      fail MemoryError, "Memory at address=#{ptr.address} is not secured with #{self}.malloc", caller
    end
  end
end

module Sodium
  module Utils

    module_function

    def check_length(data, length, description)
      if data.is_a?(String) ||data.respond_to?(:bytesize)
        unless data.bytesize == length.to_int
          fail LengthError, "Expected a length=#{length.to_int} bytes #{description}, got size=#{data.bytesize} bytes", caller
        end
      elsif data.is_a?(FFI::Pointer) ||data.respond_to?(:size)
        unless data.size == length.to_int
          fail LengthError, "Expected a length=#{length.to_int} bytes #{description}, got size=#{data.size} bytes", caller
        end
      else
        fail ArgumentError, "#{description} must be of type String or FFI::Pointer and be length=#{length.to_int} bytes long", caller
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

    def get_int(int)
      if int.is_a?(Integer)
        int
      elsif int.respond_to?(:to_int)
        int.to_int
      else
        fail ArgumentError, "#{int.class} is not a Integer", caller
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

    ZERO = "\0".force_encoding(Encoding::ASCII_8BIT).freeze

    def zeros(n)
      ZERO * n
    end
  end
end

module Sodium
  class Buffer < FFI::MemoryPointer
    def to_bytes
      read_bytes(size)
    end

    alias_method :to_str, :to_bytes
  end
end

module Sodium
  class SecretBuffer
    extend Forwardable

    def_delegators :@key, :address, :to_i

    attr_reader :size

    def initialize(size)
      @size = Utils.get_int(size)
      @key = Sodium.malloc(@size)
      setup_finalizer
    end

    def to_ptr
      @key
    end

    def free
      remove_finalizer
      readwrite
      Sodium.free(@key)
      @size = @key = nil
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

    private

    def setup_finalizer
      ObjectSpace.define_finalizer(@key, self.class.free(address))
    end

    def remove_finalizer
      ObjectSpace.undefine_finalizer @key
    end

    def self.free(address)
      ->(obj_id) do
        Sodium.readwrite(FFI::Pointer.new(address))
        Sodium.free(FFI::Pointer.new(address))
        true
      end
    end
  end
end

module RandomBytes
  extend FFI::Library
  ffi_lib :libsodium

  attach_function :randombytes_buf, [:buffer_out, :size_t], :void,  blocking: true

  attach_function :random,  :randombytes_random,  [],         :uint32,  blocking: true
  attach_function :uniform, :randombytes_uniform, [:uint32],  :uint32,  blocking: true
  attach_function :close,   :randombytes_close,   [],         :int,     blocking: true
  attach_function :stir,    :randombytes_stir,    [],         :void,    blocking: true

  def self.buf(size)
    buf = Sodium::Buffer.new(:uchar, size)
    randombytes_buf(buf, size)
    buf
  end
end

module Crypto
  module SecretBox
    extend FFI::Library
    extend Sodium::Utils

    ffi_lib :libsodium

    attach_function :primitive, :crypto_secretbox_primitive,  [], :string

    attach_function :crypto_secretbox_keybytes,   [], :size_t
    attach_function :crypto_secretbox_noncebytes, [], :size_t
    attach_function :crypto_secretbox_macbytes,   [], :size_t

    KEYBYTES    = crypto_secretbox_keybytes.freeze
    NONCEBYTES  = crypto_secretbox_noncebytes.freeze
    MACBYTES    = crypto_secretbox_macbytes.freeze

    attach_function :crypto_secretbox_easy,       [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int, blocking: true
    attach_function :crypto_secretbox_open_easy,  [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int, blocking: true

    module_function

    def nonce
      RandomBytes.buf(NONCEBYTES)
    end

    def easy(message, nonce, key)
      message_len = get_size(message)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      ciphertext = Sodium::Buffer.new(:uchar, MACBYTES + message_len)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_secretbox_easy(ciphertext, message, message_len, nonce, key)
      key.noaccess if key.is_a?(Sodium::SecretBuffer)

      ciphertext
    end

    def open_easy(ciphertext, nonce, key)
      ciphertext_len = get_size(ciphertext)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      decrypted = Sodium::Buffer.new(:uchar, ciphertext_len - MACBYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      rc = crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, key)
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
      if rc == -1
        fail CryptoError, "Ciphertext got tampered with", caller
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
        fail LengthError, "Ciphertext is too short", caller
      end

      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(key, KEYBYTES, :SecretKey)

      key.readonly if key.is_a?(Sodium::SecretBuffer)
      rc = crypto_secretbox_open_easy(ciphertext, ciphertext, ciphertext.bytesize, nonce, key)
      key.noaccess if key.is_a?(Sodium::SecretBuffer)
      if rc == -1
        fail CryptoError, "Ciphertext got tampered with", caller
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

module Crypto
  module Auth
    extend FFI::Library
    extend Sodium::Utils

    ffi_lib :libsodium

    attach_function :primitive, :crypto_auth_primitive, [], :string

    attach_function :crypto_auth_bytes,     [], :size_t
    attach_function :crypto_auth_keybytes,  [], :size_t

    BYTES     = crypto_auth_bytes.freeze
    KEYBYTES  = crypto_auth_keybytes.freeze

    attach_function :crypto_auth,         [:buffer_out, :buffer_in, :ulong_long, :buffer_in], :int, blocking: true
    attach_function :crypto_auth_verify,  [:buffer_in, :buffer_in, :ulong_long, :buffer_in],  :int, blocking: true

    module_function

    def auth(message, key)
      message_len = get_size(message)
      check_length(key, KEYBYTES, :SecretKey)

      mac = Sodium::Buffer.new(:uchar, BYTES)
      key.readonly if key.is_a?(Sodium::SecretBuffer)
      crypto_auth(mac, message, message_len, key)
      key.noaccess if key.is_a?(Sodium::SecretBuffer)

      mac
    end

    def verify(mac, message, key)
      check_length(mac, BYTES, :Mac)
      message_len = get_size(message)
      check_length(key, KEYBYTES, :SecretKey)

      key.readonly if key.is_a?(Sodium::SecretBuffer)
      rc = crypto_auth_verify(mac, message, message_len, key)
      key.noaccess if key.is_a?(Sodium::SecretBuffer)

      rc == 0
    end
  end

  def self.auth(*args)
    Auth.auth(*args)
  end
end

module Crypto
  module AEAD
    module Chacha20Poly1305
      extend FFI::Library
      extend Sodium::Utils

      ffi_lib :libsodium

      attach_function :crypto_aead_chacha20poly1305_keybytes,   [], :size_t
      attach_function :crypto_aead_chacha20poly1305_npubbytes,  [], :size_t
      attach_function :crypto_aead_chacha20poly1305_abytes,     [], :size_t

      PRIMITIVE = 'chacha20poly1305'.freeze
      KEYBYTES  = crypto_aead_chacha20poly1305_keybytes.freeze
      NPUBBYTES = crypto_aead_chacha20poly1305_npubbytes.freeze
      ABYTES    = crypto_aead_chacha20poly1305_abytes.freeze

      attach_function :crypto_aead_chacha20poly1305_encrypt,  [:buffer_out, :buffer_inout, :buffer_in, :ulong_long, :buffer_in, :ulong_long, :pointer, :buffer_in, :buffer_in], :int
      attach_function :crypto_aead_chacha20poly1305_decrypt,  [:buffer_out, :buffer_inout, :pointer, :buffer_in, :ulong_long, :buffer_in, :ulong_long, :buffer_in, :buffer_in], :int

      module_function

      def primitive
        PRIMITIVE
      end

      def nonce
        RandomBytes.buf(NPUBBYTES)
      end

      def encrypt(message, additional_data, nonce, key)
        message_len = get_size(message)
        additional_data_len = get_size(additional_data)
        check_length(nonce, NPUBBYTES, :Nonce)
        check_length(key, KEYBYTES, :SecretKey)

        ciphertext = Sodium::Buffer.new(:uchar, message_len + ABYTES)
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

        decrypted = Sodium::Buffer.new(:uchar, ciphertext_len - ABYTES)
        key.readonly if key.is_a?(Sodium::SecretBuffer)
        rc = crypto_aead_chacha20poly1305_decrypt(decrypted, nil, nil, ciphertext, ciphertext_len, additional_data, additional_data_len, nonce, key)
        key.noaccess if key.is_a?(Sodium::SecretBuffer)
        if rc == -1
          fail CryptoError, "Ciphertext got tampered with", caller
        end

        decrypted
      end
    end
  end
end

module Crypto
  module Box
    extend FFI::Library
    extend Sodium::Utils

    ffi_lib :libsodium

    attach_function :primitive, :crypto_box_primitive,  [], :string

    attach_function :crypto_box_seedbytes,      [], :size_t
    attach_function :crypto_box_publickeybytes, [], :size_t
    attach_function :crypto_box_secretkeybytes, [], :size_t
    attach_function :crypto_box_noncebytes,     [], :size_t
    attach_function :crypto_box_macbytes,       [], :size_t

    SEEDBYTES       = crypto_box_seedbytes.freeze
    PUBLICKEYBYTES  = crypto_box_publickeybytes.freeze
    SECRETKEYBYTES  = crypto_box_secretkeybytes.freeze
    NONCEBYTES      = crypto_box_noncebytes.freeze
    MACBYTES        = crypto_box_macbytes.freeze

    attach_function :crypto_box_keypair,      [:buffer_out, :buffer_out],             :int, blocking: true
    attach_function :crypto_box_seed_keypair, [:buffer_out, :buffer_out, :buffer_in], :int, blocking: true

    attach_function :crypto_box_easy,       [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in, :buffer_in], :int, blocking: true
    attach_function :crypto_box_open_easy,  [:buffer_out, :buffer_in, :ulong_long, :buffer_in, :buffer_in, :buffer_in], :int, blocking: true

    module_function

    def nonce
      RandomBytes.buf(NONCEBYTES)
    end

    def keypair
      public_key = Sodium::Buffer.new(:uchar, PUBLICKEYBYTES)
      secret_key = Sodium::Buffer.new(:uchar, SECRETKEYBYTES)
      crypto_box_keypair(public_key, secret_key)

      [public_key, secret_key]
    end

    def seed_keypair(seed)
      check_length(seed, SEEDBYTES, :Seed)

      public_key = Sodium::Buffer.new(:uchar, PUBLICKEYBYTES)
      secret_key = Sodium::Buffer.new(:uchar, SECRETKEYBYTES)
      crypto_box_seed_keypair(public_key, secret_key, seed)

      [public_key, secret_key]
    end

    def memory_locked_keypair
      public_key = Sodium::Buffer.new(:uchar, PUBLICKEYBYTES)
      secret_key = Sodium::SecretBuffer.new(SECRETKEYBYTES)
      crypto_box_keypair(public_key, secret_key)
      secret_key.noaccess

      [public_key, secret_key]
    end

    def memory_locked_seed_keypair(seed)
      check_length(seed, SEEDBYTES, :Seed)

      public_key = Sodium::Buffer.new(:uchar, PUBLICKEYBYTES)
      secret_key = Sodium::SecretBuffer.new(:uchar, SECRETKEYBYTES)
      crypto_box_seed_keypair(public_key, secret_key, seed)
      secret_key.noaccess

      [public_key, secret_key]
    end

    def easy(message, nonce, public_key, secret_key)
      message_len = get_size(message)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      ciphertext = Sodium::Buffer.new(:uchar, MACBYTES + message_len)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      crypto_box_easy(ciphertext, message, message_len, nonce, public_key, secret_key)
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)

      ciphertext
    end

    def open_easy(ciphertext, nonce, public_key, secret_key)
      ciphertext_len = get_size(ciphertext)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      decrypted = Sodium::Buffer.new(:uchar, ciphertext_len - MACBYTES)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      rc = crypto_box_open_easy(decrypted, ciphertext, ciphertext_len, nonce, public_key, secret_key)
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
      if rc == -1
        fail CryptoError, "Ciphertext got tampered with", caller
      end

      decrypted
    end

    def easy_in_place(data, nonce, public_key, secret_key)
      message = get_string(data)
      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      message_len = message.bytesize
      message << zeros(MACBYTES)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      crypto_box_easy(message, message, message_len, nonce, public_key, secret_key)
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)

      message
    end

    def open_easy_in_place(data, nonce, public_key, secret_key, utf8 = false)
      ciphertext = get_string(data)
      unless (message_len = ciphertext.bytesize - MACBYTES) > 0
        fail LengthError, "Ciphertext is too short", caller
      end

      check_length(nonce, NONCEBYTES, :Nonce)
      check_length(public_key, PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, SECRETKEYBYTES, :SecretKey)

      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      rc = crypto_box_open_easy(ciphertext, ciphertext, ciphertext.bytesize, nonce, public_key, secret_key)
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
      if rc == -1
        fail CryptoError, "Ciphertext got tampered with", caller
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

module Crypto
  module GenericHash
    extend FFI::Library
    extend Sodium::Utils

    ffi_lib :libsodium

    attach_function :primitive, :crypto_generichash_primitive,  [], :string

    attach_function :crypto_generichash_bytes_min,      [], :size_t
    attach_function :crypto_generichash_bytes_max,      [], :size_t
    attach_function :crypto_generichash_bytes,          [], :size_t
    attach_function :crypto_generichash_keybytes_min,   [], :size_t
    attach_function :crypto_generichash_keybytes_max,   [], :size_t
    attach_function :crypto_generichash_keybytes,       [], :size_t

    BYTES_MIN     = crypto_generichash_bytes_min.freeze
    BYTES_MAX     = crypto_generichash_bytes_max.freeze
    BYTES         = crypto_generichash_bytes.freeze
    KEYBYTES_MIN  = crypto_generichash_keybytes_min.freeze
    KEYBYTES_MAX  = crypto_generichash_keybytes_max.freeze
    KEYBYTES      = crypto_generichash_keybytes.freeze

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

    module_function

    def generichash(message, hash_size = BYTES, key = nil)
      message_len = get_size(message)
      if hash_size > BYTES_MAX ||hash_size < BYTES_MIN
        fail LengthError, "Hash size must be between #{BYTES_MIN} and #{BYTES_MAX} bytes, got size=#{hash_size.to_int} bytes", caller
      end

      if key
        key_len = get_size(key)

        if key_len > KEYBYTES_MAX ||key_len < KEYBYTES_MIN
          fail LengthError, "Key length must be between #{KEYBYTES_MIN} and #{KEYBYTES_MAX} bytes, got length=#{key_len} bytes", caller
        end
      else
        key_len = 0
      end

      blake2b = Sodium::Buffer.new(:uchar, hash_size)
      if crypto_generichash(blake2b, hash_size, message, message_len, key, key_len) == -1
        fail CryptoError
      end

      blake2b
    end

    def init(key = nil, hash_size = BYTES)
      if key
        key_len = get_size(key)

        if key_len > KEYBYTES_MAX ||key_len < KEYBYTES_MIN
          fail LengthError, "Key length must be between #{KEYBYTES_MIN} and #{KEYBYTES_MAX} bytes, got length=#{key_len} bytes", caller
        end
      else
        key_len = 0
      end

      if hash_size > BYTES_MAX ||hash_size < BYTES_MIN
        fail LengthError, "Hash size must be between #{BYTES_MIN} and #{BYTES_MAX} bytes, got size=#{hash_size.to_int} bytes", caller
      end

      state = State.new
      blake2b = Sodium::Buffer.new(:uchar, hash_size)
      if crypto_generichash_init(state, key, key_len, hash_size) == -1
        fail CryptoError
      end

      [state, blake2b]
    end

    def update(state, message)
      get_pointer(state)
      message_len = get_size(message)

      if crypto_generichash_update(state, message, message_len) == -1
        fail CryptoError
      end
    end

    def final(state, blake2b)
      get_pointer(state)
      get_pointer(blake2b)

      if crypto_generichash_final(state, blake2b, blake2b.size) == -1
        fail CryptoError
      end

      blake2b
    end
  end

  def self.generichash(*args)
    GenericHash.generichash(*args)
  end
end

module Crypto
  module PwHash
    module ScryptSalsa208SHA256
      PACK_C = 'c*'.freeze
      extend FFI::Library
      extend Sodium::Utils

      ffi_lib :libsodium

      attach_function :crypto_pwhash_scryptsalsa208sha256_saltbytes,            [], :size_t
      attach_function :crypto_pwhash_scryptsalsa208sha256_strbytes,             [], :size_t
      attach_function :crypto_pwhash_scryptsalsa208sha256_strprefix,            [], :string
      attach_function :crypto_pwhash_scryptsalsa208sha256_opslimit_interactive, [], :size_t
      attach_function :crypto_pwhash_scryptsalsa208sha256_memlimit_interactive, [], :size_t
      attach_function :crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive,   [], :size_t
      attach_function :crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive,   [], :size_t

      PRIMITIVE             = 'scryptsalsa208sha256'.freeze
      SALTBYTES             = crypto_pwhash_scryptsalsa208sha256_saltbytes.freeze
      STRBYTES              = crypto_pwhash_scryptsalsa208sha256_strbytes.freeze
      STRPREFIX             = crypto_pwhash_scryptsalsa208sha256_strprefix.freeze
      OPSLIMIT_INTERACTIVE  = crypto_pwhash_scryptsalsa208sha256_opslimit_interactive.freeze
      MEMLIMIT_INTERACTIVE  = crypto_pwhash_scryptsalsa208sha256_memlimit_interactive.freeze
      OPSLIMIT_SENSITIVE    = crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive.freeze
      MEMLIMIT_SENSITIVE    = crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive.freeze

      attach_function :crypto_pwhash_scryptsalsa208sha256,            [:buffer_out, :ulong_long, :buffer_in, :ulong_long, :buffer_in, :ulong_long, :size_t],  :int, blocking: true
      attach_function :crypto_pwhash_scryptsalsa208sha256_str,        [:buffer_out, :buffer_in, :ulong_long, :ulong_long, :size_t],                           :int, blocking: true
      attach_function :crypto_pwhash_scryptsalsa208sha256_str_verify, [:buffer_in, :buffer_in, :ulong_long],                                                  :int, blocking: true

      module_function

      def primitive
        PRIMITIVE
      end

      def salt
        RandomBytes.buf(SALTBYTES)
      end

      def scryptsalsa208sha256(passwd, outlen, salt, opslimit = OPSLIMIT_INTERACTIVE, memlimit = MEMLIMIT_INTERACTIVE)
        passwd_len = get_size(passwd)
        check_length(salt, SALTBYTES, :Salt)
        if opslimit < OPSLIMIT_INTERACTIVE
          raise LengthError, "Opslimit must be at least #{OPSLIMIT_INTERACTIVE}, got #{opslimit.to_int}"
        end
        if memlimit < MEMLIMIT_INTERACTIVE
          raise LengthError, "Memlimit must be at least #{MEMLIMIT_INTERACTIVE}, got #{memlimit.to_int}"
        end

        out = Sodium::SecretBuffer.new(outlen)
        rc = crypto_pwhash_scryptsalsa208sha256(out, outlen, passwd, passwd_len, salt, opslimit, memlimit)
        out.noaccess
        if rc == -1
          fail NoMemoryError, "Failed to allocate memory max size=#{memlimit.to_int} bytes", caller
        end

        out
      end

      def str(passwd, opslimit = OPSLIMIT_INTERACTIVE, memlimit = MEMLIMIT_INTERACTIVE)
        passwd_len = get_size(passwd)
        if opslimit < OPSLIMIT_INTERACTIVE
          raise LengthError, "Opslimit must be at least #{OPSLIMIT_INTERACTIVE}, got #{opslimit.to_int}"
        end
        if memlimit < MEMLIMIT_INTERACTIVE
          raise LengthError, "Memlimit must be at least #{MEMLIMIT_INTERACTIVE}, got #{memlimit.to_int}"
        end

        hashed_password = FFI::MemoryPointer.new(:char, STRBYTES)
        if crypto_pwhash_scryptsalsa208sha256_str(hashed_password, passwd, passwd_len, opslimit, memlimit) == -1
          fail NoMemoryError, "Failed to allocate memory max size=#{memlimit.to_int} bytes", caller
        end

        hashed_password.read_array_of_char(STRBYTES).pack(PACK_C)
      end

      def str_verify(str, passwd)
        check_length(str, STRBYTES, :Str)
        passwd_len = get_size(passwd)

        crypto_pwhash_scryptsalsa208sha256_str_verify(str, passwd, passwd_len) == 0
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
