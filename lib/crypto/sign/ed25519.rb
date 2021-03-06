﻿require 'ffi'
require_relative '../../sodium/utils'
require_relative '../scalar_mult'
require_relative '../../sodium/secret_buffer'

module Crypto
  module Sign
    module Ed25519
      PRIMITIVE = 'ed25519'.freeze
      extend FFI::Library
      extend Sodium::Utils

      ffi_lib :libsodium

      class << self
        def crypto_sign_ed25519_primitive
          PRIMITIVE
        end

        alias_method :primitive, :crypto_sign_ed25519_primitive
      end

      attach_function :publickeybytes,  :crypto_sign_ed25519_publickeybytes,  [], :size_t
      attach_function :secretkeybytes,  :crypto_sign_ed25519_secretkeybytes,  [], :size_t
      attach_function :seedbytes,       :crypto_sign_ed25519_seedbytes,       [], :size_t

      PUBLICKEYBYTES  = publickeybytes.freeze
      SECRETKEYBYTES  = secretkeybytes.freeze
      SEEDBYTES       = seedbytes.freeze

      attach_function :crypto_sign_ed25519_pk_to_curve25519,  [:buffer_out, :buffer_in],  :int
      attach_function :crypto_sign_ed25519_sk_to_curve25519,  [:buffer_out, :buffer_in],  :int

      attach_function :crypto_sign_ed25519_sk_to_seed,  [:buffer_out, :buffer_in],  :int
      attach_function :crypto_sign_ed25519_sk_to_pk,    [:buffer_out, :buffer_in],  :int

      module_function

      def pk_to_curve25519(public_key)
        check_length(public_key, PUBLICKEYBYTES, :PublicKey)

        curve25519_pk = zeros(ScalarMult::BYTES)
        crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, public_key)

        curve25519_pk
      end

      def sk_to_curve25519(secret_key)
        check_length(secret_key, SECRETKEYBYTES, :SecretKey)

        curve25519_sk = Sodium::SecretBuffer.new(ScalarMult::BYTES)
        secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
        crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, secret_key)
        curve25519_sk.noaccess

        curve25519_sk
      ensure
        secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
      end

      def sk_to_seed(secret_key)
        check_length(secret_key, SECRETKEYBYTES, :SecretKey)

        seed = zeros(SEEDBYTES)
        secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
        crypto_sign_ed25519_sk_to_seed(seed, secret_key)

        seed
      ensure
        secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
      end

      def sk_to_pk(secret_key)
        check_length(secret_key, SECRETKEYBYTES, :SecretKey)

        public_key = zeros(PUBLICKEYBYTES)
        secret_key.readonly if secret_key.is_a?(Sodium::SecretBuffer)
        crypto_sign_ed25519_sk_to_pk(seed, secret_key)

        public_key
      ensure
        secret_key.noaccess if secret_key.is_a?(Sodium::SecretBuffer)
      end
    end

    Ed25519.freeze
  end
end
