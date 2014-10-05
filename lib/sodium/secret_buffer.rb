require_relative '../sodium'

module Sodium
  class SecretBuffer
    extend Forwardable

    def_delegators :@buffer, :address, :to_i

    attr_reader :size

    def initialize(size)
      @size = Utils.get_int(size)
      @buffer = Sodium.malloc(@size)
      setup_finalizer
    end

    def to_ptr
      @buffer
    end

    def free
      remove_finalizer
      readwrite
      Sodium.free(@buffer)
      @size = @buffer = nil
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
      ObjectSpace.define_finalizer(@buffer, self.class.free(address))
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
