require_relative '../sodium'
require_relative '../sodium/utils'
require_relative '../sodium/buffer'
require_relative '../sodium/secret_buffer'
require_relative '../random_bytes'

module Crypto
  module ScalarMult
    extend FFI::Library
    extend Sodium::Utils

    ffi_lib :libsodium

    attach_function :primitive,   :crypto_scalarmult_primitive,   [], :string
    attach_function :bytes,       :crypto_scalarmult_bytes,       [], :size_t
    attach_function :scalarbytes, :crypto_scalarmult_scalarbytes, [], :size_t

    PRIMITIVE   = primitive.freeze
    BYTES       = bytes.freeze
    SCALARBYTES = scalarbytes.freeze

    attach_function :crypto_scalarmult_base,  [:buffer_out, :buffer_in],              :int
    attach_function :crypto_scalarmult,       [:buffer_out, :buffer_in, :buffer_in],  :int

    module_function

    def base(secret_key)
      check_length(secret_key, SCALARBYTES, :SecretKey)

      public_key = Sodium::Buffer.new(:uchar, BYTES)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      crypto_scalarmult_base(public_key, secret_key)
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)

      public_key
    end

    def scalarmut(secret_key, public_key)
      check_length(secret_key, SCALARBYTES, :SecretKey)
      check_length(public_key, SCALARBYTES, :PublicKey)

      shared_secret = Sodium::SecretBuffer.new(BYTES)
      secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
      crypto_scalarmult(shared_secret, secret_key, public_key)
      secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
      shared_secret.noaccess

      shared_secret
    end
  end

  def self.scalarmut(*args)
    ScalarMult.scalarmut(*args)
  end
end
