require 'forwardable'
require_relative 'utils'
require_relative '../sodium'
require 'ffi'

module Sodium
  class SecretBuffer
    extend Forwardable

    def_delegators :@buffer, :address, :to_i

    attr_reader :size, :primitive

    def initialize(size, primitive = nil)
      @size = Utils.get_int(size)
      @primitive = primitive
      @buffer = Sodium.malloc(size)
      setup_finalizer
    end

    def to_ptr
      @buffer
    end

    def free
      remove_finalizer
      readwrite
      Sodium.free(@buffer)
      @size = @primitive = @buffer = nil
    end

    def noaccess
      Sodium.noaccess(@buffer)
    end

    def readonly
      Sodium.readonly(@buffer)
    end

    def readwrite
      Sodium.readwrite(@buffer)
    end

    private

    def setup_finalizer
      ObjectSpace.define_finalizer(@buffer, self.class.free(@buffer.address))
    end

    def remove_finalizer
      ObjectSpace.undefine_finalizer @buffer
    end

    def self.free(address)
      ->(obj_id) do
        Sodium.readwrite(FFI::Pointer.new(address))
        Sodium.free(FFI::Pointer.new(address))
        true
      end
    end
  end
end
