module Iodine
  module Storage
    class InMemStore
      def initialize
        @storage = {}
      end

      def fetch(identity, key)
        @storage.fetch(identity).fetch(key)
      end

      def store(identity, key, value)
        unless (id = @storage[identity])
          id = @storage[identity] = {}.compare_by_identity
        end

        id.store(key, value)
      end
    end

    InMemStore.freeze
  end
end
