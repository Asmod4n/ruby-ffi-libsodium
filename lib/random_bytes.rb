require 'ffi'
require_relative 'sodium/buffer'

module RandomBytes
  extend FFI::Library
  ffi_lib :libsodium

  attach_function :randombytes_buf, [:buffer_out, :size_t], :void

  attach_function :random,  :randombytes_random,  [],         :uint32
  attach_function :uniform, :randombytes_uniform, [:uint32],  :uint32
  attach_function :close,   :randombytes_close,   [],         :int
  attach_function :stir,    :randombytes_stir,    [],         :void

  module_function

  def buf(size)
    buf = Sodium::Buffer.new(:void, size)
    randombytes_buf(buf, size)
    buf
  end
end

RandomBytes.freeze
