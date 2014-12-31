iodine
======

basic usage
===========

```ruby
bob_chain = Iodine::Keychain.new
```

create a user
-------------
```ruby
bob_public_key = bob_chain.auth('bob', 'bob')
```

authenticate a user
-------------------
```ruby
bob = bob_chain.verify('bob', 'bob')
```

Secret-Key Encryption
===================

encrypt a plaintext
-------------------
```ruby
ciphertext = bob.secretbox('plaintext')
```

decrypt a ciphertext
--------------------
```ruby
bob.secretbox_open(ciphertext)
```

Public-Key Encryption
=====================
```ruby
alice_chain = Iodine::Keychain.new

alice_chain.store_public_key('bob', bob_public_key)
alice_public_key = alice_chain.auth('alice', 'alice')
bob_chain.store_public_key('alice', alice_public_key)

alice = alice_chain.verify('alice', 'alice')
```

encrypt a plaintext
--------------------
```ruby
ciphertext = bob.box('hello', 'alice')
```

decrypt a ciphertext
--------------------
```ruby
alice.box_open(ciphertext)
```
