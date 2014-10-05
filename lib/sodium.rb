require 'ffi'

module Sodium
  class CryptoError < StandardError; end
  class LengthError < ArgumentError; end
  class MemoryError < StandardError; end

  extend FFI::Library
  ffi_lib :libsodium

  attach_function :init,  :sodium_init, [], :int,  blocking: true

  attach_function :memcmp,  :sodium_memcmp,   [:buffer_in, :buffer_in, :size_t],  :int
  attach_function :memzero, :sodium_memzero,  [:pointer, :size_t],  :void,    blocking: true
  attach_function :free,    :sodium_free,     [:pointer],           :void,    blocking: true
  attach_function :sodium_mlock,              [:pointer, :size_t],  :int,     blocking: true
  attach_function :sodium_munlock,            [:pointer, :size_t],  :int,     blocking: true
  attach_function :sodium_malloc,             [:size_t],            :pointer, blocking: true
  attach_function :sodium_allocarray,         [:size_t, :size_t],   :pointer, blocking: true
  attach_function :sodium_mprotect_noaccess,  [:pointer],           :int,     blocking: true
  attach_function :sodium_mprotect_readonly,  [:pointer],           :int,     blocking: true
  attach_function :sodium_mprotect_readwrite, [:pointer],           :int,     blocking: true

  module_function

  def mlock(addr, len)
    if sodium_mlock(addr, len) == -1
      raise MemoryError, "Could not lock length=#{len.to_int} bytes memory at address=#{addr.address}", caller
    end
  end

  def munlock(addr, len)
    if sodium_munlock(addr, len) == -1
      raise MemoryError, "Could not unlock length=#{len.to_int} bytes memory at address=#{addr.address}", caller
    end
  end

  def malloc(size)
    unless (mem = sodium_malloc(size))
      raise NoMemoryError, "Failed to allocate memory size=#{size.to_int} bytes", caller
    end
    mem
  end

  def allocarray(count, size)
    unless (mem = sodium_allocarray(count, size))
      raise NoMemoryError, "Failed to allocate memory size=#{count.to_int * size.to_int} bytes", caller
    end
    mem
  end

  def noaccess(ptr)
    if sodium_mprotect_noaccess(ptr) == -1
      raise MemoryError, "Memory at address=#{ptr.address} is not secured with #{self}.malloc", caller
    end
  end

  def readonly(ptr)
    if sodium_mprotect_readonly(ptr) == -1
      raise MemoryError, "Memory at address=#{ptr.address} is not secured with #{self}.malloc", caller
    end
  end

  def readwrite(ptr)
    if sodium_mprotect_readwrite(ptr) == -1
      raise MemoryError, "Memory at address=#{ptr.address} is not secured with #{self}.malloc", caller
    end
  end
end
