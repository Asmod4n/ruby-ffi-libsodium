ruby-ffi-sodium
===============

"Two Factor Authentication": All you need to store to verify a account is the salt, which can be public. Even when compromised, passwords should be safe. See: http://doc.libsodium.org/secret-key_cryptography/secret-key_authentication.html

```ruby
require './sodium'

password = 'test123'

salt = Sodium::Pwhash::ScryptSalsa208SHA256.salt
key = Sodium::Pwhash.scryptsalsa208sha256(password, Sodium::Auth::KEYBYTES, salt)
mac = Sodium.auth(password, key)

puts Sodium::Auth.verify(mac, password, key)
```
