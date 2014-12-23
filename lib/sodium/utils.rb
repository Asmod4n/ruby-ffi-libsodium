require_relative 'core_ext'
require_relative 'errors'

module Sodium
  module Utils

    module_function

    def get_size(data)
      if data.respond_to?(:bytesize)
        data.bytesize
      else
        data.size
      end
    end

    def check_length(data, length, description)
      if data.respond_to?(:bytesize)
        data.bytesize == length || fail(LengthError, "Expected a length=#{length} bytes #{description}, got bytesize=#{data.bytesize} bytes", caller)
      else
        data.size == length || fail(LengthError, "Expected a length=#{length} bytes #{description}, got size=#{data.size} bytes", caller)
      end
    end

    ZERO = "\0".force_encoding(Encoding::ASCII_8BIT).freeze

    def zeros(n)
      ZERO * n
    end

    HEXY = 'H*'.freeze

    def bin2hex(bytes)
      String(bytes).unpack(HEXY).first
    end

    def hex2bin(hex)
      [String(hex)].pack(HEXY)
    end
  end

  Utils.freeze
end
