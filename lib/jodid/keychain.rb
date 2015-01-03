require 'forwardable'
require 'base64'

module Jodid
  class Keychain
    extend Forwardable

    attr_reader :storage
    def_delegators :@storage, :has_identity?, :fetch, :fetch_identity,
    :store, :delete, :delete_identity

    def initialize(options = {}, &key_not_found)
      @storage = options.fetch(:storage) do
        require_relative 'storage/in_mem_store'
        Storage::InMemStore.new(options, &key_not_found)
      end
    end

    def auth(identity, password)
      salt = Crypto::PwHash::ScryptSalsa208SHA256.salt
      key = Crypto::PwHash::ScryptSalsa208SHA256.scryptsalsa208sha256(
        Crypto::AEAD::Chacha20Poly1305::KEYBYTES, password, salt)
      nonce = Crypto::AEAD::Chacha20Poly1305.nonce
      seed = RandomBytes.buf(Crypto::Sign::SEEDBYTES)
      ciphertext = Crypto::AEAD::Chacha20Poly1305.encrypt(seed,
        identity, nonce, key)
      pk, sk = Crypto::Sign.memory_locked_seed_keypair(seed)
      Sodium.memzero(seed, Crypto::Sign::SEEDBYTES)
      @storage.store(identity, :salt, salt)
      @storage.store(identity, :nonce, nonce)
      @storage.store(identity, :ciphertext, ciphertext)
      store_public_key(identity, pk)
      Base64.strict_encode64(pk)
    ensure
      Sodium.memzero(password, password.bytesize)
      password.clear
    end

    def verify(identity, password)
      key = Crypto::PwHash::ScryptSalsa208SHA256.scryptsalsa208sha256(
        Crypto::AEAD::Chacha20Poly1305::KEYBYTES, password,
        @storage.fetch(identity, :salt))
      seed = Crypto::AEAD::Chacha20Poly1305.decrypt(
        @storage.fetch(identity, :ciphertext),
        identity, @storage.fetch(identity, :nonce), key)
      cryptor = Cryptor.new(*Crypto::Sign.memory_locked_seed_keypair(seed), self)
      Sodium.memzero(seed, Crypto::Sign::SEEDBYTES)
      cryptor
    ensure
      Sodium.memzero(password, password.bytesize)
      password.clear
    end

    def store_public_key(identity, public_key)
      case public_key.bytesize
      when 64 # hex
        @storage.store_public_key(identity, Sodium::Utils.hex2bin(public_key))
      when 44 # base64
        @storage.store_public_key(identity, Base64.strict_decode64(public_key))
      when 32 # raw
        @storage.store_public_key(identity, public_key)
      else
        fail Sodium::LengthError, "public_key is not in hex, base64 or raw encoding", caller
      end
    end
  end

  Keychain.freeze
end
