require 'ffi'
require_relative 'errors'

module Sodium
  module Mprotect
    extend FFI::Library
    ffi_lib :libsodium

    attach_function :sodium_mprotect_noaccess,  [:pointer], :int
    attach_function :sodium_mprotect_readonly,  [:pointer], :int
    attach_function :sodium_mprotect_readwrite, [:pointer], :int

    module_function

    def noaccess(ptr)
      sodium_mprotect_noaccess(ptr) == 0 || raise(MemoryError, "Memory at address=#{ptr.address} is not secured with Sodium.malloc", caller)
    end

    def readonly(ptr)
      sodium_mprotect_readonly(ptr) == 0 || raise(MemoryError, "Memory at address=#{ptr.address} is not secured with Sodium.malloc", caller)
    end

    def readwrite(ptr)
      sodium_mprotect_readwrite(ptr) == 0 || raise(MemoryError, "Memory at address=#{ptr.address} is not secured with Sodium.malloc", caller)
    end
  end

  Mprotect.freeze
end
