ruby-ffi-sodium
===============

"Two Factor Authentication": The server never stores the password this way, but only a message authentication code which can be verified using the right password. All you need to store to verify a account is the salt and the mac, which both can be public. See: http://doc.libsodium.org/secret-key_cryptography/secret-key_authentication.html

```ruby
require './sodium'

password = 'test123'

salt = Sodium::Pwhash::ScryptSalsa208SHA256.salt
key = Sodium::Pwhash.scryptsalsa208sha256(password, Sodium::Auth::KEYBYTES, salt)
mac = Sodium.auth(password, key)

puts Sodium::Auth.verify(mac, password, key)
```
