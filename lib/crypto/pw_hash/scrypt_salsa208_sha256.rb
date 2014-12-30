require 'ffi'
require_relative '../../sodium/utils'
require_relative '../../random_bytes'
require_relative '../../sodium/errors'
require_relative '../../sodium/secret_buffer'

module Crypto
  module PwHash
    module ScryptSalsa208SHA256
      PRIMITIVE = 'scryptsalsa208sha256'.freeze

      extend FFI::Library
      extend Sodium::Utils

      ffi_lib :libsodium

      class << self
        def crypto_pwhash_scryptsalsa208sha256_primitive
          PRIMITIVE
        end

        alias_method :primitive, :crypto_pwhash_scryptsalsa208sha256_primitive
      end

      attach_function :saltbytes, :crypto_pwhash_scryptsalsa208sha256_saltbytes,  [], :size_t
      attach_function :strbytes,  :crypto_pwhash_scryptsalsa208sha256_strbytes,   [], :size_t
      attach_function :strprefix, :crypto_pwhash_scryptsalsa208sha256_strprefix,  [], :string
      attach_function :opslimit_interactive,  :crypto_pwhash_scryptsalsa208sha256_opslimit_interactive, [], :size_t
      attach_function :memlimit_interactive,  :crypto_pwhash_scryptsalsa208sha256_memlimit_interactive, [], :size_t
      attach_function :opslimit_sensitive,    :crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive,   [], :size_t
      attach_function :memlimit_sensitive,    :crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive,   [], :size_t

      SALTBYTES             = saltbytes.freeze
      STRBYTES              = strbytes.freeze
      STRPREFIX             = strprefix.freeze
      OPSLIMIT_INTERACTIVE  = opslimit_interactive.freeze
      MEMLIMIT_INTERACTIVE  = memlimit_interactive.freeze
      OPSLIMIT_SENSITIVE    = opslimit_sensitive.freeze
      MEMLIMIT_SENSITIVE    = memlimit_sensitive.freeze

      attach_function :crypto_pwhash_scryptsalsa208sha256,            [:buffer_out, :ulong_long, :string, :ulong_long, :buffer_in, :ulong_long, :size_t], :int
      attach_function :crypto_pwhash_scryptsalsa208sha256_str,        [:buffer_out, :string, :ulong_long, :ulong_long, :size_t],                          :int
      attach_function :crypto_pwhash_scryptsalsa208sha256_str_verify, [:string, :string, :ulong_long],                                                    :int

      module_function

      def salt
        RandomBytes.buf(SALTBYTES)
      end

      def scryptsalsa208sha256(outlen, passwd, salt, opslimit = OPSLIMIT_INTERACTIVE, memlimit = MEMLIMIT_INTERACTIVE)
        check_length(salt, SALTBYTES, :Salt)

        out = Sodium::SecretBuffer.new(outlen)
        if crypto_pwhash_scryptsalsa208sha256(out, outlen, passwd, passwd.bytesize, salt, opslimit, memlimit) == -1
          raise NoMemoryError, "Failed to allocate memory max size=#{memlimit} bytes", caller
        end

        out.noaccess
        out
      end

      def str(passwd, opslimit = OPSLIMIT_INTERACTIVE, memlimit = MEMLIMIT_INTERACTIVE)
        hashed_password = zeros(STRBYTES)
        if crypto_pwhash_scryptsalsa208sha256_str(hashed_password, passwd, passwd.bytesize, opslimit, memlimit) == -1
          raise NoMemoryError, "Failed to allocate memory max size=#{memlimit} bytes", caller
        end

        hashed_password.chop!
      end

      def str_verify(str, passwd)
        check_length(str, STRBYTES - 1, :Str)
        crypto_pwhash_scryptsalsa208sha256_str_verify(str, passwd, passwd.bytesize) == 0
      end
    end

    ScryptSalsa208SHA256.freeze

    module_function

    def scryptsalsa208sha256(*args)
      ScryptSalsa208SHA256.scryptsalsa208sha256(*args)
    end
  end

  PwHash.freeze
end
