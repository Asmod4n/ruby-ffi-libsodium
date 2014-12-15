require 'ffi'

module Sodium
  class Buffer < FFI::MemoryPointer
    def to_str
      read_bytes(size)
    end
  end

  Buffer.freeze
end
