ruby-ffi-libsodium
===============

Requirements
------------

ruby >= 1.9.3

libsodium >= 1.0.1

Deterministically derive a keypair from a password without storing the password or secret key
---------------------------------------------------------------------------------------------

```ruby
def auth(identity, password)
  salt = Crypto::PwHash::ScryptSalsa208SHA256.salt
  key = Crypto::PwHash.scryptsalsa208sha256(
    Crypto::AEAD::Chacha20Poly1305::KEYBYTES, password, salt)
  nonce = Crypto::AEAD::Chacha20Poly1305.nonce
  seed = RandomBytes.buf(Crypto::Sign::SEEDBYTES)
  ciphertext = Crypto::AEAD::Chacha20Poly1305.encrypt(seed,
    identity, nonce, key)
  Sodium.memzero(seed, Crypto::Sign::SEEDBYTES)
  {salt: salt, nonce: nonce, ciphertext: ciphertext}
end

def verify(identity, password, salt, nonce, ciphertext)
  key = Crypto::PwHash.scryptsalsa208sha256(
    Crypto::AEAD::Chacha20Poly1305::KEYBYTES, password, salt)
  seed = Crypto::AEAD::Chacha20Poly1305.decrypt(ciphertext,
    identity, nonce, key)
  pk, sk = Crypto::Sign.memory_locked_seed_keypair(seed)
  Sodium.memzero(seed, Crypto::Sign::SEEDBYTES)
  {public_key: pk, secret_key: sk}
end
```
