require_relative '../sodium'
require 'ffi'

module Sodium
  module Utils

    module_function

    def check_length(data, length, description)
      if data.is_a?(String) ||data.respond_to?(:bytesize)
        unless data.bytesize == length.to_int
          fail Sodium::LengthError, "Expected a length=#{length.to_int} bytes #{description}, got size=#{data.bytesize} bytes", caller
        end
      elsif data.is_a?(FFI::Pointer) ||data.respond_to?(:size)
        unless data.size == length.to_int
          fail Sodium::LengthError, "Expected a length=#{length.to_int} bytes #{description}, got size=#{data.size} bytes", caller
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
      elsif data.nil?
        0
      else
        fail ArgumentError, "#{data.class} doesn't respond to :bytesize or :size", caller
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
end
