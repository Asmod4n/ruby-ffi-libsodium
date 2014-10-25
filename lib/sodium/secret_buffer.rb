require 'forwardable'
require_relative 'utils'
require_relative '../sodium'
require 'ffi'

module Sodium
  class SecretBuffer
    extend Forwardable

    def_delegators :to_ptr, :address, :to_i

    attr_reader :size, :primitive, :to_ptr

    def initialize(size, primitive = nil)
      @size = Utils.get_int(size)
      @primitive = primitive
      @to_ptr = Sodium.malloc(self.size)
      setup_finalizer
    end

    def free
      remove_finalizer
      readwrite
      Sodium.free(to_ptr)
      @size = @primitive = @to_ptr = nil
    end

    def noaccess
      Sodium.noaccess(to_ptr)
    end

    def readonly
      Sodium.readonly(to_ptr)
    end

    def readwrite
      Sodium.readwrite(to_ptr)
    end

    private

    def setup_finalizer
      ObjectSpace.define_finalizer(to_ptr, self.class.free(to_ptr.address))
    end

    def remove_finalizer
      ObjectSpace.undefine_finalizer to_ptr
    end

    def self.free(address)
      ->(obj_id) do
        ptr = FFI::Pointer.new(address)
        Sodium.readwrite(ptr)
        Sodium.free(ptr)
        true
      end
    end
  end
end
