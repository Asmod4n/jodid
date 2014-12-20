require 'czmq/zconfig'

module Iodine
  class Keychain
    def initialize(directory)
      @directory = directory
      @mtime = File.mtime(@directory)
      @identities = {}
      Dir.glob(File.join(@directory, '*.id')) do |id_file|
        @identities[File.basename(id_file, '.id')] = CZMQ::Zconfig.load(id_file)
      end
    end

    def lookup(identity, path)
      if ((mtime = File.mtime(@directory)) != @mtime)
        @mtime = mtime
        load_ids
      end

      if (id = @identities[identity])
        id.reload if id.has_changed
        id.resolve(path, nil)
      end
    end

    def store(identity, path, value)
      id_file = File.join(@directory, "#{identity}.id")
      unless (id = @identities[identity])
        File.new(id_file, 'w+').close
        id = @identities[identity] = CZMQ::Zconfig.load(id_file)
      end

      id.put(path, value)
      id.save(id_file)
      self
    end

    def load_ids
      Dir.glob(File.join(@directory, '*.id')) do |id_file|
        identity = File.basename(id_file, '.id')
        if (id = @identities[identity])
          id.reload if id.has_changed
        else
          @identities[identity] = CZMQ::Zconfig.load(id_file)
        end
      end
    end
  end
end
