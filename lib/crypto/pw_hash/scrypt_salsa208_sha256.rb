require 'ffi'
require_relative '../../sodium/utils'
require_relative '../../random_bytes'
require_relative '../../sodium'
require_relative '../../sodium/secret_buffer'

module Crypto
  module PwHash
    module ScryptSalsa208SHA256
      PACK_C    = 'c*'.freeze
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

      attach_function :crypto_pwhash_scryptsalsa208sha256,            [:buffer_out, :ulong_long, :buffer_in, :ulong_long, :buffer_in, :ulong_long, :size_t],  :int, blocking: true
      attach_function :crypto_pwhash_scryptsalsa208sha256_str,        [:buffer_out, :buffer_in, :ulong_long, :ulong_long, :size_t],                           :int, blocking: true
      attach_function :crypto_pwhash_scryptsalsa208sha256_str_verify, [:buffer_in, :buffer_in, :ulong_long],                                                  :int, blocking: true

      module_function

      def salt
        RandomBytes.buf(SALTBYTES)
      end

      def scryptsalsa208sha256(outlen, passwd, salt, opslimit = OPSLIMIT_INTERACTIVE, memlimit = MEMLIMIT_INTERACTIVE)
        passwd_len = get_size(passwd)
        check_length(salt, SALTBYTES, :Salt)
        if opslimit < OPSLIMIT_INTERACTIVE
          fail Sodium::LengthError, "Opslimit must be at least #{OPSLIMIT_INTERACTIVE}, got #{opslimit.to_int}", caller
        end
        if memlimit < MEMLIMIT_INTERACTIVE
          fail Sodium::LengthError, "Memlimit must be at least #{MEMLIMIT_INTERACTIVE}, got #{memlimit.to_int}", caller
        end

        out = Sodium::SecretBuffer.new(outlen)
        rc = crypto_pwhash_scryptsalsa208sha256(out, outlen, passwd, passwd_len, salt, opslimit, memlimit)
        out.noaccess
        if rc == -1
          raise NoMemoryError, "Failed to allocate memory max size=#{memlimit.to_int} bytes", caller
        end

        out
      end

      def str(passwd, opslimit = OPSLIMIT_INTERACTIVE, memlimit = MEMLIMIT_INTERACTIVE)
        passwd_len = get_size(passwd)
        if opslimit < OPSLIMIT_INTERACTIVE
          fail Sodium::LengthError, "Opslimit must be at least #{OPSLIMIT_INTERACTIVE}, got #{opslimit.to_int}", caller
        end
        if memlimit < MEMLIMIT_INTERACTIVE
          fail Sodium::LengthError, "Memlimit must be at least #{MEMLIMIT_INTERACTIVE}, got #{memlimit.to_int}", caller
        end

        hashed_password = FFI::MemoryPointer.new(:char, STRBYTES)
        if crypto_pwhash_scryptsalsa208sha256_str(hashed_password, passwd, passwd_len, opslimit, memlimit) == -1
          raise NoMemoryError, "Failed to allocate memory max size=#{memlimit.to_int} bytes", caller
        end

        hashed_password.read_array_of_char(STRBYTES).pack(PACK_C)
      end

      def str_verify(str, passwd)
        check_length(str, STRBYTES, :Str)
        passwd_len = get_size(passwd)

        crypto_pwhash_scryptsalsa208sha256_str_verify(str, passwd, passwd_len) == 0
      end
    end

    module_function

    def scryptsalsa208sha256(*args)
      ScryptSalsa208SHA256.scryptsalsa208sha256(*args)
    end
  end
end
