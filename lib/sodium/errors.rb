module Sodium
  CryptoError = Class.new(StandardError).freeze
  LengthError = Class.new(ArgumentError).freeze
  MemoryError = Class.new(StandardError).freeze
end
