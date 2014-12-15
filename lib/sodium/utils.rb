require 'ffi'
require_relative 'secret_buffer'
require_relative 'errors'

module Sodium
  module Utils

    module_function

    def get_size(data)
      case data
      when FFI::Pointer, SecretBuffer
        data.size
      when String
        data.bytesize
      when NilClass
        0
      else
        fail TypeError, "#{data.class} must be of type FFI::Pointer, Sodium::SecretBufffer, String or NilClass", caller
      end
    end

    def check_length(data, length, description)
      case data
      when FFI::Pointer, SecretBuffer
        if data.size == length
          true
        else
          fail LengthError, "Expected a length=#{length} bytes #{description}, got size=#{data.size} bytes", caller
        end
      when String
        if data.bytesize == length
          true
        else
          fail LengthError, "Expected a length=#{length} bytes #{description}, got size=#{data.bytesize} bytes", caller
        end
      else
        fail TypeError, "#{data.class} must be of type FFI::Pointer, Sodium::SecretBufffer or String", caller
      end
    end

    ZERO = "\0".force_encoding(Encoding::ASCII_8BIT).freeze

    def zeros(n)
      ZERO * n
    end

    HEXY = 'H*'.freeze

    def bin2hex(bytes)
      bytes.to_str.unpack(HEXY).first
    end

    def hex2bin(hex)
      [hex].pack(HEXY)
    end
  end

  Utils.freeze
end
