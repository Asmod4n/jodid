module Iodine
  class Cryptor
    def initialize(public_key, secret_key, keychain)
      @public_key = public_key
      @secret_key = secret_key
      @keychain = keychain

      @shared_secrets = {}
    end

    def secret_box(value)
      nonce = Crypto::SecretBox.nonce
      nonce << Crypto::SecretBox.secretbox(value, nonce, @secret_key)
    end

    def secret_box_open(ciphertext, encoding = Encoding.default_external)
      Crypto::SecretBox.open( ciphertext[Crypto::SecretBox::NONCEBYTES..-1],
                              ciphertext[0...Crypto::SecretBox::NONCEBYTES],
                              @secret_key,
                              encoding)
    end

    def secret_box!(value)
      data = String(value)
      nonce = Crypto::SecretBox.nonce
      Crypto::SecretBox.secretbox!(data, nonce, @secret_key).prepend(nonce)
    end

    def secret_box_open!(ciphertext, encoding = Encoding.default_external)
      nonce = ciphertext.slice!(0...Crypto::SecretBox::NONCEBYTES)
      Crypto::SecretBox.open!(ciphertext,
                              nonce,
                              @secret_key,
                              encoding)
    end

    def box(value, recipient)
      public_key = @keychain.fetch(recipient, :public_key)
      shared_secret = @shared_secrets.fetch(public_key) do
        @shared_secrets.store(public_key, Crypto::Box.beforenm(public_key, @secret_key))
      end
      nonce = Crypto::Box.nonce
      ciphertext = Crypto::SecretBox.secretbox(value, nonce, shared_secret)
      @public_key.dup << nonce << ciphertext
    end

    def box_open(ciphertext, encoding = Encoding.default_external)
      public_key = ciphertext[0...Crypto::Box::PUBLICKEYBYTES]
      shared_secret = @shared_secrets.fetch(public_key) do
        @shared_secrets.store(public_key, Crypto::Box.beforenm(public_key, @secret_key))
      end
      Crypto::SecretBox.open(
        ciphertext[Crypto::Box::PUBLICKEYBYTES + Crypto::Box::NONCEBYTES..-1],
        ciphertext[Crypto::Box::PUBLICKEYBYTES, Crypto::Box::NONCEBYTES],
        shared_secret,
        encoding)
    end

    def box!(value, recipient)
      public_key = @keychain.fetch(recipient, :public_key)
      shared_secret = @shared_secrets.fetch(public_key) do
        @shared_secrets.store(public_key, Crypto::Box.beforenm(public_key, @secret_key))
      end
      data = String(value)
      nonce = Crypto::Box.nonce
      Crypto::SecretBox.secretbox!(data, nonce, shared_secret).prepend(nonce).prepend(@public_key)
    end

    def box_open!(ciphertext, encoding = Encoding.default_external)
      public_key = ciphertext.slice!(0...Crypto::Box::PUBLICKEYBYTES)
      shared_secret = @shared_secrets.fetch(public_key) do
        @shared_secrets.store(public_key, Crypto::Box.beforenm(public_key, @secret_key))
      end
      nonce = ciphertext.slice!(0...Crypto::Box::NONCEBYTES)
      Crypto::SecretBox.open!(ciphertext,
                        nonce,
                        shared_secret,
                        encoding)
    end
  end

  Cryptor.freeze
end
