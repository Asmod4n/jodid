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
      unless (id = @identities[identity])
        id_file = File.join(@directory, "#{identity}.id")
        id = @identities[File.basename(id_file, '.id')] = CZMQ::Zconfig.new('root', nil)
      end

      id.put(path, value)
      id.save(File.join(@directory, "#{identity}.id"))
      self
    end

    def load_ids
      Dir.glob(File.join(@directory, '*.id')) do |id_file|
        @identities[File.basename(id_file, '.id')] = CZMQ::Zconfig.load(id_file)
      end
    end
  end
end
