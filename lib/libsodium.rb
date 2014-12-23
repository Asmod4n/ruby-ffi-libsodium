require_relative 'sodium/core_ext'
require_relative 'sodium/errors'
require_relative 'sodium'
require_relative 'sodium/utils'
require_relative 'sodium/mprotect'
require_relative 'sodium/secret_buffer'
Sodium.freeze
require_relative 'random_bytes'
require_relative 'crypto/secret_box'
require_relative 'crypto/auth'
require_relative 'crypto/aead/chacha20_poly1305'
require_relative 'crypto/box'
require_relative 'crypto/sign/ed25519'
require_relative 'crypto/sign'
require_relative 'crypto/generic_hash'
require_relative 'crypto/short_hash'
require_relative 'crypto/pw_hash/scrypt_salsa208_sha256'
require_relative 'crypto/one_time_auth'
require_relative 'crypto/scalar_mult'
Crypto.freeze

Thread.exclusive do
  if Sodium.init == -1
    fail LoadError, 'Could not initialize sodium'
  end
end
