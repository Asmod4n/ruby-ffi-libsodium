﻿require 'ffi'
require_relative 'sodium/errors'
require_relative 'sodium/utils'

module Sodium
  extend FFI::Library
  extend Utils
  ffi_lib :libsodium

  attach_function :init,  :sodium_init, [], :int

  attach_function :memcmp,  :sodium_memcmp,   [:buffer_in, :buffer_in, :size_t],  :int
  attach_function :memzero, :sodium_memzero,  [:pointer, :size_t],  :void
  attach_function :free,    :sodium_free,     [:pointer],           :void
  attach_function :sodium_mlock,              [:pointer, :size_t],  :int
  attach_function :sodium_munlock,            [:pointer, :size_t],  :int
  attach_function :sodium_malloc,             [:size_t],            :pointer
  attach_function :sodium_allocarray,         [:size_t, :size_t],   :pointer

  attach_function :sodium_bin2hex,  [:buffer_out, :size_t, :buffer_in, :size_t],  :string
  attach_function :sodium_hex2bin,  [:buffer_out, :size_t, :string, :size_t, :string, :buffer_out, :pointer],  :int

  module_function

  def mlock(addr, len)
    if sodium_mlock(addr, len) == -1
      raise MemoryError, "Could not lock length=#{len} bytes memory at address=#{addr.address}", caller
    end

    true
  end

  def munlock(addr, len)
    if sodium_munlock(addr, len) == -1
      raise MemoryError, "Could not unlock length=#{len} bytes memory at address=#{addr.address}", caller
    end

    true
  end

  def malloc(size)
    if (mem = sodium_malloc(size)).null?
      raise NoMemoryError, "Failed to allocate memory size=#{size} bytes", caller
    end

    mem
  end

  def allocarray(count, size)
    if (mem = sodium_allocarray(count, size)).null?
      raise NoMemoryError, "Failed to allocate memory size=#{count * size} bytes", caller
    end

    mem
  end

  def bin2hex(bin)
    bin_len = get_size(bin)
    hex = zeros(bin_len * 2 + 1)
    sodium_bin2hex(hex, hex.bytesize, bin, bin_len)
  end

  def hex2bin(hex, bin_maxlen, ignore = nil)
    bin = zeros(bin_maxlen)
    bin_len = FFI::MemoryPointer.new(:size_t)
    if sodium_hex2bin(bin, bin_maxlen, hex, hex.bytesize, ignore, bin_len, nil) == -1
      raise LengthError, "bin_maxlen=#{bin_maxlen} is too short", caller
    end
    size = bin_len.size == 8 ? bin_len.get_uint64(0) : bin_len.get_uint32(0)

    [bin, size]
  end

  def hex2bin!(hex, bin_maxlen, ignore = nil)
    bin_len = FFI::MemoryPointer.new(:size_t)
    if sodium_hex2bin(hex, bin_maxlen, hex, hex.bytesize, ignore, bin_len, nil) == -1
      raise LengthError, "bin_maxlen=#{bin_maxlen} is too short", caller
    end
    size = bin_len.size == 8 ? bin_len.get_uint64(0) : bin_len.get_uint32(0)
    hex.slice!(size..-1)
    hex
  end
end
