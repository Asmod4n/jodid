require 'forwardable'

module Iodine
  class Keychain
    extend Forwardable

    attr_reader :storage
    def_delegators :@storage, :fetch, :store

    def initialize(options = {})
      @storage = options.fetch(:storage) do
        require_relative 'storage/in_mem_store'
        Storage::InMemStore.new
      end
    end

    def auth(identity, password)
      salt = Crypto::PwHash::ScryptSalsa208SHA256.salt
      secret_key = Crypto::PwHash::ScryptSalsa208SHA256.scryptsalsa208sha256(
        Crypto::OneTimeAuth::KEYBYTES,
        password,
        salt)
      public_key = Crypto::ScalarMult.base(secret_key)
      mac = Crypto::OneTimeAuth.onetimeauth(password, secret_key)
      @storage.store(identity, :salt, salt)
      @storage.store(identity, :public_key, public_key)
      @storage.store(identity, :mac, mac)
      Libzmq.z85_encode public_key
    ensure
      password.clear
    end

    def verify(identity, password)
      secret_key = Crypto::PwHash::ScryptSalsa208SHA256.scryptsalsa208sha256(
        Crypto::OneTimeAuth::KEYBYTES,
        password,
        @storage.fetch(identity, :salt))

      if Crypto::OneTimeAuth.verify( @storage.fetch(identity, :mac),
                              password,
                              secret_key)

        Cryptor.new(@storage.fetch(identity, :public_key), secret_key, self)
      end
    ensure
      password.clear
    end
  end

  Keychain.freeze
end
