require 'forwardable'
require_relative '../sodium'
require_relative 'mprotect'
require 'ffi'

module Sodium
  class SecretBuffer
    extend Forwardable

    attr_reader :size, :to_ptr
    def_delegators :@to_ptr, :address, :to_i

    def initialize(size)
      @size = Integer(size)
      @to_ptr = Sodium.malloc(@size)
      ObjectSpace.define_finalizer(@to_ptr, self.class.free(@to_ptr.address))
    end

    def free
      ObjectSpace.undefine_finalizer @to_ptr
      Sodium::Mprotect.readonly(@to_ptr)
      Sodium.free(@to_ptr)
      remove_instance_variable(:@size)
      remove_instance_variable(:@to_ptr)
      true
    end

    def noaccess
      Sodium::Mprotect.noaccess(@to_ptr)
    end

    def readonly
      Sodium::Mprotect.readonly(@to_ptr)
    end

    def readwrite
      Sodium::Mprotect.readwrite(@to_ptr)
    end

    private

    def self.free(address)
      ->(obj_id) do
        ptr = FFI::Pointer.new(address)
        Sodium::Mprotect.readonly(ptr)
        Sodium.free(ptr)
        true
      end
    end
  end

  SecretBuffer.freeze
end
