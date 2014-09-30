ruby-ffi-sodium
===============

Secret Key derivation and user authentication: Store the salt and the mac and you can verify a user and give him a Secret Key without storing the password or key in a database.

```ruby
require './sodium'

password = 'test123'

salt = Sodium::Pwhash::ScryptSalsa208SHA256.salt
key = Sodium::Pwhash.scryptsalsa208sha256(password, Sodium::Auth::KEYBYTES, salt)
mac = Sodium.auth(password, key)

puts Sodium::Auth.verify(mac, password, key)
```
