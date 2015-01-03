module Jodid
  module Storage
    class InMemStore
      include Sodium::Utils

      def initialize(options = {}, &key_not_found)
        @key_not_found = key_not_found

        @storage = {}
        @pk_to_id = {}
      end

      def has_identity?(identity)
        @storage.has_key?(identity)
      end

      def fetch(identity, key)
        @storage.fetch(identity, &@key_not_found).fetch(key, &@key_not_found)
      end

      def fetch_identity(public_key)
        case public_key.bytesize
        when 64 # hex
          @pk_to_id.fetch(Sodium::Utils.hex2bin(public_key))
        when 44 # base64
          @pk_to_id.fetch(Base64.strict_decode64(public_key))
        when 32 # raw
          @pk_to_id.fetch(public_key)
        else
          fail Sodium::LengthError, "public_key is not in hex, base64 or raw encoding", caller
        end
      end

      def store(identity, key, value)
        id = @storage.fetch(identity) do
          @storage.store(identity, {}.compare_by_identity)
        end

        id.store(key, value)
      end

      def store_public_key(identity, public_key)
        check_length(public_key, Crypto::Sign::PUBLICKEYBYTES, :PublicKey)

        store(identity, :public_key, public_key)
        @pk_to_id.store(public_key, identity)
      end

      def delete(identity, key)
        @storage.fetch(identity, &@key_not_found).delete(key)
      end

      def delete_identity(identity)
        @storage.delete(identity)
      end
    end

    InMemStore.freeze
  end
end
