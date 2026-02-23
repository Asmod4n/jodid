This it not maintained.

 jodid
======

[RubyDoc](http://www.rubydoc.info/github/Asmod4n/jodid/master)

Requirements
============
[ruby](https://www.ruby-lang.org/) >= 1.9.3

[libsodium](http://doc.libsodium.org) >= 1.0.1


Installation instructions
=========================

Mac OS X/Linux
--------------
```bash
brew install libsodium
```

Generic
-------
```
gem install --prerelease jodid
```

Basic usage
===========

```ruby
bob_chain = Jodid::Keychain.new
```

Create a user
-------------
```ruby
bob_public_key = bob_chain.auth('bob', 'bob')
```

Authenticate a user
-------------------
```ruby
bob = bob_chain.verify('bob', 'bob')
```

Secret-Key Encryption
===================

Encrypt a plaintext
-------------------
```ruby
ciphertext = bob.secretbox('plaintext')
```

Decrypt a ciphertext
--------------------
```ruby
bob.secretbox_open(ciphertext)
```

Public-Key Encryption
=====================
```ruby
alice_chain = Jodid::Keychain.new

alice_chain.store_public_key('bob', bob_public_key)
alice_public_key = alice_chain.auth('alice', 'alice')
bob_chain.store_public_key('alice', alice_public_key)

alice = alice_chain.verify('alice', 'alice')
```

Encrypt a plaintext
--------------------
```ruby
ciphertext = bob.box('hello', 'alice')
```

Decrypt a ciphertext
--------------------
```ruby
puts alice.box_open(ciphertext)
puts alice_chain.fetch_identity(ciphertext[0...Crypto::Box::PUBLICKEYBYTES])
```

Public-Key Signatures
=====================
```ruby
message = 'good morning'
```

Generate a signature for a message
----------------------------------
```ruby
sigature = alice.sign_detached(message)
```

Verify a message signature
--------------------------
```ruby
alice.sign_verify_detached(signature, message)
```
