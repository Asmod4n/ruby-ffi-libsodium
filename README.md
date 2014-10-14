ruby-ffi-libsodium
===============

Secret Key derivation and user authentication: Store the salt and the mac and you can verify a user and give him a Secret Key without storing the password or key in a database.

```bash
bundle update
```

```ruby
require 'bundler/setup'
require 'libsodium'

password = 'test123'

salt = Crypto::PwHash::ScryptSalsa208SHA256.salt
key = Crypto::PwHash.scryptsalsa208sha256(Crypto::Auth::KEYBYTES, password, salt)
mac = Crypto.auth(password, key)

puts Crypto::Auth.verify(mac, password, key)
```
