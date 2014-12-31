iodine
======

basic usage
===========

```ruby
keychain = Iodine::Keychain.new
```

create a user
-------------
```ruby
bob_public_key = keychain.auth('bob', 'bob')
```

authenticate a user
-------------------
```ruby
bob = keychain.verify('bob', 'bob')
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
alice_public_key = keychain.auth('alice', 'alice')
alice = keychain.verify('alice', 'alice')
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
