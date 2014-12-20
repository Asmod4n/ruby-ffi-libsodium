﻿require 'ffi'
require_relative 'sodium/errors'
require_relative 'sodium/utils'
require_relative 'sodium/buffer'

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
  attach_function :sodium_hex2bin,  [:buffer_out, :size_t, :buffer_in, :size_t, :string, :pointer, :pointer],  :int

  module_function

  def mlock(addr, len)
    sodium_mlock(addr, len) == 0 || raise(MemoryError, "Could not lock length=#{len} bytes memory at address=#{addr.address}", caller)
  end

  def munlock(addr, len)
    sodium_munlock(addr, len) == 0 || raise(MemoryError, "Could not unlock length=#{len} bytes memory at address=#{addr.address}", caller)
  end

  def malloc(size)
    sodium_malloc(size) || raise(NoMemoryError, "Failed to allocate memory size=#{size} bytes", caller)
  end

  def allocarray(count, size)
    sodium_allocarray(count, size) || raise(NoMemoryError, "Failed to allocate memory size=#{count * size} bytes", caller)
  end

  def bin2hex(bin)
    bin_len = get_size(bin)
    hex = FFI::MemoryPointer.new(:char, bin_len * 2 + 1)
    sodium_bin2hex(hex, hex.size, bin, bin_len)
  end

  def hex2bin(hex, ignore = nil)
    if ignore
      bin_maxlen = hex.tr(ignore, '').bytesize / 2
    else
      bin_maxlen = hex.bytesize / 2
    end

    bin = Sodium::Buffer.new(:uchar, bin_maxlen)
    sodium_hex2bin(bin, bin_maxlen, hex, hex.bytesize, ignore, nil, nil)
    bin
  end
end
