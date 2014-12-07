require 'ffi'
require_relative 'sodium/errors'
require_relative 'sodium/utils'
require_relative 'sodium/buffer'

module Sodium
  extend FFI::Library
  ffi_lib :libsodium

  attach_function :init,  :sodium_init, [], :int

  attach_function :memcmp,  :sodium_memcmp,   [:buffer_in, :buffer_in, :size_t],  :int
  attach_function :memzero, :sodium_memzero,  [:pointer, :size_t],  :void
  attach_function :free,    :sodium_free,     [:pointer],           :void
  attach_function :sodium_mlock,              [:pointer, :size_t],  :int
  attach_function :sodium_munlock,            [:pointer, :size_t],  :int
  attach_function :sodium_malloc,             [:size_t],            :pointer
  attach_function :sodium_allocarray,         [:size_t, :size_t],   :pointer
  attach_function :sodium_mprotect_noaccess,  [:pointer],           :int
  attach_function :sodium_mprotect_readonly,  [:pointer],           :int
  attach_function :sodium_mprotect_readwrite, [:pointer],           :int

  module_function

  def mlock(addr, len)
    unless sodium_mlock(addr, len).zero?
      raise MemoryError, "Could not lock length=#{len} bytes memory at address=#{addr.address}", caller
    end
  end

  def munlock(addr, len)
    unless sodium_munlock(addr, len).zero?
      raise MemoryError, "Could not unlock length=#{len} bytes memory at address=#{addr.address}", caller
    end
  end

  def malloc(size)
    unless (mem = sodium_malloc(size))
      raise NoMemoryError, "Failed to allocate memory size=#{size} bytes", caller
    end
    mem
  end

  def allocarray(count, size)
    unless (mem = sodium_allocarray(count, size))
      raise NoMemoryError, "Failed to allocate memory size=#{count * size} bytes", caller
    end
    mem
  end

  def noaccess(ptr)
    unless sodium_mprotect_noaccess(ptr).zero?
      raise MemoryError, "Memory at address=#{ptr.address} is not secured with #{self}.malloc", caller
    end
  end

  def readonly(ptr)
    unless sodium_mprotect_readonly(ptr).zero?
      raise MemoryError, "Memory at address=#{ptr.address} is not secured with #{self}.malloc", caller
    end
  end

  def readwrite(ptr)
    unless sodium_mprotect_readwrite(ptr).zero?
      raise MemoryError, "Memory at address=#{ptr.address} is not secured with #{self}.malloc", caller
    end
  end
end
