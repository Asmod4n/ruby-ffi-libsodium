﻿require_relative 'sodium/buffer'

module RandomBytes
  extend FFI::Library
  ffi_lib :libsodium

  attach_function :randombytes_buf, [:buffer_out, :size_t], :void,  blocking: true

  attach_function :random,  :randombytes_random,  [],         :uint32,  blocking: true
  attach_function :uniform, :randombytes_uniform, [:uint32],  :uint32,  blocking: true
  attach_function :close,   :randombytes_close,   [],         :int,     blocking: true
  attach_function :stir,    :randombytes_stir,    [],         :void,    blocking: true

  module_function

  def buf(size)
    buf = Sodium::Buffer.new(:uchar, size)
    randombytes_buf(buf, size)
    buf
  end
end