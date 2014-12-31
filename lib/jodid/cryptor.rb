module Jodid
  class Cryptor
    include Sodium::Utils

    attr_reader :public_key

    def initialize(public_key, secret_key, keychain)
      check_length(public_key, Crypto::Box::PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, Crypto::Box::SECRETKEYBYTES, :SecretKey)

      @public_key = public_key
      @secret_key = secret_key
      @keychain = keychain

      @shared_secrets = {}
    end

    def secretbox(value)
      nonce = Crypto::SecretBox.nonce
      nonce << Crypto::SecretBox.secretbox(value, nonce, @secret_key)
    end

    def secretbox_open(ciphertext, encoding = Encoding.default_external)
      Crypto::SecretBox.open(
        ciphertext[Crypto::SecretBox::NONCEBYTES..-1],
        ciphertext[0...Crypto::SecretBox::NONCEBYTES],
        @secret_key, encoding)
    end

    def secretbox!(value)
      data = String(value)
      nonce = Crypto::SecretBox.nonce
      Crypto::SecretBox.secretbox!(data, nonce,
        @secret_key).prepend(nonce)
    end

    def secretbox_open!(ciphertext, encoding = Encoding.default_external)
      nonce = ciphertext.slice!(0...Crypto::SecretBox::NONCEBYTES)
      Crypto::SecretBox.open!(ciphertext, nonce,
                              @secret_key, encoding)
    end

    def box(value, recipient)
      public_key = @keychain.fetch(recipient, :public_key)
      shared_secret = @shared_secrets.fetch(public_key) do
        @shared_secrets.store(public_key,
          Crypto::Box.beforenm(public_key, @secret_key))
      end
      nonce = Crypto::Box.nonce
      ciphertext = Crypto::SecretBox.secretbox(value, nonce,
        shared_secret)
      @public_key.dup << nonce << ciphertext
    end

    def box_open(ciphertext, encoding = Encoding.default_external)
      public_key = ciphertext[0...Crypto::Box::PUBLICKEYBYTES]
      if (shared_secret = @shared_secrets[public_key])
        message = Crypto::SecretBox.open(
          ciphertext[Crypto::Box::PUBLICKEYBYTES + Crypto::Box::NONCEBYTES..-1],
          ciphertext[Crypto::Box::PUBLICKEYBYTES, Crypto::Box::NONCEBYTES],
          shared_secret, encoding)
      else
        message = Crypto::Box.open(
          ciphertext[Crypto::Box::PUBLICKEYBYTES + Crypto::Box::NONCEBYTES..-1],
          ciphertext[Crypto::Box::PUBLICKEYBYTES, Crypto::Box::NONCEBYTES],
          public_key, @secret_key, encoding)
        @shared_secrets.store(public_key,
          Crypto::Box.beforenm(public_key, @secret_key))
      end

      message
    end

    def box!(value, recipient)
      public_key = @keychain.fetch(recipient, :public_key)
      shared_secret = @shared_secrets.fetch(public_key) do
        @shared_secrets.store(public_key,
          Crypto::Box.beforenm(public_key, @secret_key))
      end
      data = String(value)
      nonce = Crypto::Box.nonce
      Crypto::SecretBox.secretbox!(data, nonce,
        shared_secret).prepend(nonce).prepend(@public_key)
    end

    def box_open!(ciphertext, encoding = Encoding.default_external)
      public_key = ciphertext.slice!(0...Crypto::Box::PUBLICKEYBYTES)
      nonce = ciphertext.slice!(0...Crypto::Box::NONCEBYTES)
      if (shared_secret = @shared_secrets[public_key])
        message = Crypto::SecretBox.open!(ciphertext, nonce,
          shared_secret, encoding)
      else
        message = Crypto::Box.open!(ciphertext, nonce,
          public_key, @secret_key, encoding)
        @shared_secrets.store(public_key,
          Crypto::Box.beforenm(public_key, @secret_key))
      end

      message
    end
  end

  Cryptor.freeze
end
