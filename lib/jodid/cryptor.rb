module Jodid
  class Cryptor
    include Sodium::Utils

    attr_reader :public_key

    def initialize(public_key, secret_key, keychain)
      check_length(public_key, Crypto::Sign::PUBLICKEYBYTES, :PublicKey)
      check_length(secret_key, Crypto::Sign::SECRETKEYBYTES, :SecretKey)

      @public_key = public_key
      @secret_key = secret_key
      @curve25519_sk = Crypto::Sign::Ed25519.sk_to_curve25519(@secret_key)
      @keychain = keychain

      @shared_secrets = {}
    end

    def secretbox(value)
      nonce = Crypto::SecretBox.nonce
      nonce << Crypto::SecretBox.secretbox(value, nonce, @curve25519_sk)
    end

    def secretbox_open(ciphertext, encoding = Encoding.default_external)
      Crypto::SecretBox.open(
        ciphertext[Crypto::SecretBox::NONCEBYTES..-1],
        ciphertext[0...Crypto::SecretBox::NONCEBYTES],
        @curve25519_sk, encoding)
    end

    def secretbox!(value)
      data = String(value)
      nonce = Crypto::SecretBox.nonce
      Crypto::SecretBox.secretbox!(data, nonce,
        @curve25519_sk).prepend(nonce)
    end

    def secretbox_open!(ciphertext, encoding = Encoding.default_external)
      nonce = ciphertext.slice!(0...Crypto::SecretBox::NONCEBYTES)
      Crypto::SecretBox.open!(ciphertext, nonce,
                              @curve25519_sk, encoding)
    end

    def box(value, recipient)
      public_key = @keychain.fetch(recipient, :public_key)
      shared_secret = @shared_secrets.fetch(public_key) do
        @shared_secrets.store(public_key,
          Crypto::Box.beforenm(
            Crypto::Sign::Ed25519.pk_to_curve25519(public_key),
            @curve25519_sk))
      end
      nonce = Crypto::Box.nonce
      ciphertext = Crypto::SecretBox.secretbox(value, nonce,
        shared_secret)
      @public_key.dup << nonce << ciphertext
    end

    def box_open(ciphertext, encoding = Encoding.default_external)
      public_key = ciphertext[0...Crypto::Sign::PUBLICKEYBYTES]
      if (shared_secret = @shared_secrets[public_key])
        message = Crypto::SecretBox.open(
          ciphertext[Crypto::Sign::PUBLICKEYBYTES + Crypto::Box::NONCEBYTES..-1],
          ciphertext[Crypto::Sign::PUBLICKEYBYTES, Crypto::Box::NONCEBYTES],
          shared_secret, encoding)
      else
        pk = Crypto::Sign::Ed25519.pk_to_curve25519(public_key)
        message = Crypto::Box.open(
          ciphertext[Crypto::Sign::PUBLICKEYBYTES + Crypto::Box::NONCEBYTES..-1],
          ciphertext[Crypto::Sign::PUBLICKEYBYTES, Crypto::Box::NONCEBYTES],
          pk, @curve25519_sk, encoding)
        @shared_secrets.store(public_key,
          Crypto::Box.beforenm(
            pk, @curve25519_sk))
      end

      message
    end

    def box!(value, recipient)
      public_key = @keychain.fetch(recipient, :public_key)
      shared_secret = @shared_secrets.fetch(public_key) do
        @shared_secrets.store(public_key,
          Crypto::Box.beforenm(
            Crypto::Sign::Ed25519.pk_to_curve25519(public_key),
            @curve25519_sk))
      end
      data = String(value)
      nonce = Crypto::Box.nonce
      Crypto::SecretBox.secretbox!(data, nonce,
        shared_secret).prepend(nonce).prepend(@public_key)
    end

    def box_open!(ciphertext, encoding = Encoding.default_external)
      public_key = ciphertext.slice!(0...Crypto::Sign::PUBLICKEYBYTES)
      nonce = ciphertext.slice!(0...Crypto::Box::NONCEBYTES)
      if (shared_secret = @shared_secrets[public_key])
        message = Crypto::SecretBox.open!(ciphertext, nonce,
          shared_secret, encoding)
      else
        pk = Crypto::Sign::Ed25519.pk_to_curve25519(public_key)
        message = Crypto::Box.open!(ciphertext, nonce,
          pk, @curve25519_sk, encoding)
        @shared_secrets.store(public_key,
          Crypto::Box.beforenm(pk, @curve25519_sk))
      end

      message
    end

    def sign_detached(message)
      Crypto::Sign.detached(message, @secret_key).prepend(@public_key)
    end

    def sign_verify_detached(signature, message)
      public_key = signature[0...Crypto::Sign::PUBLICKEYBYTES]
      Crypto::Sign.verify_detached(
        signature[Crypto::Sign::PUBLICKEYBYTES..-1],
        message, public_key)
    end
  end

  Cryptor.freeze
end
