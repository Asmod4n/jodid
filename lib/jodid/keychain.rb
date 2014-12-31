require 'forwardable'
require 'base64'

module Jodid
  class Keychain
    extend Forwardable

    attr_reader :storage
    def_delegators :@storage, :fetch, :fetch_identity, :store, :delete, :delete_identity

    def initialize(options = {})
      @storage = options.fetch(:storage) do
        require_relative 'storage/in_mem_store'
        Storage::InMemStore.new
      end
    end

    def auth(identity, password)
      salt = Crypto::PwHash::ScryptSalsa208SHA256.salt
      secret_key = Crypto::PwHash::ScryptSalsa208SHA256.scryptsalsa208sha256(
        Crypto::OneTimeAuth::KEYBYTES, password, salt)
      public_key = Crypto::ScalarMult.base(secret_key)
      mac = Crypto::OneTimeAuth.onetimeauth(password, secret_key)
      @storage.store(identity, :salt, salt)
      store_public_key(identity, public_key)
      @storage.store(identity, :mac, mac)
      Base64.strict_encode64 public_key
    ensure
      password.clear
    end

    def verify(identity, password)
      secret_key = Crypto::PwHash::ScryptSalsa208SHA256.scryptsalsa208sha256(
        Crypto::OneTimeAuth::KEYBYTES, password,
        @storage.fetch(identity, :salt))

      if Crypto::OneTimeAuth.verify(@storage.fetch(identity, :mac),
        password, secret_key)

        Cryptor.new(@storage.fetch(identity, :public_key), secret_key, self)
      end
    ensure
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
