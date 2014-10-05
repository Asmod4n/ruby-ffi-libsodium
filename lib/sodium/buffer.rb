require 'ffi'

module Sodium
  class Buffer < FFI::MemoryPointer
    def to_bytes
      read_bytes(size)
    end

    alias_method :to_str, :to_bytes
  end
end
