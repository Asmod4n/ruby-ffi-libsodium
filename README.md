ruby-ffi-sodium
===============

Secret Key derivation and user authentication: Store the salt and the mac and you can verify a user and give him a Secret Key without storing the password or key in a database.

```ruby
require './sodium'

password = 'test123'

salt = Crypto::Pwhash::ScryptSalsa208SHA256.salt
key = Crypto::Pwhash.scryptsalsa208sha256(password, Crypto::Auth::KEYBYTES, salt)
mac = Crypto.auth(password, key)

puts Crypto::Auth.verify(mac, password, key)
```
