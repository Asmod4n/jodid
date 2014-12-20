require 'czmq/zconfig'

module Iodine
  class Keychain
    def initialize(directory)
      @directory = directory
      @identities = {}
      @mtime = File.mtime(@directory)
      Dir.glob(File.join(@directory, '*.id')) do |id_file|
        @identities[File.basename(id_file, '.id')] = CZMQ::Zconfig.load(id_file)
      end
    end

    def lookup(identity, path)
      if ((mtime = File.mtime(@directory)) != @mtime)
        @mtime = mtime
        load_ids
      end

      if @identities[identity]
        if @identities[identity].has_changed
          id_file = File.join(@directory, "#{identity}.id")
          unless File.dirname(id_file) == @directory
            fail ArgumentError, "identity=#{identity} contains illegal characters", caller
          end
          @identities[identity] = CZMQ::Zconfig.load(id_file)
        end

        @identities[identity].resolve(path, nil)
      end
    end

    def store(identity, path, value)
      id_file = File.join(@directory, "#{identity}.id")
      unless File.dirname(id_file) == @directory
        fail ArgumentError, "identity=#{identity} contains illegal characters", caller
      end

      unless (id = @identities[identity])
        File.new(id_file, 'w+').close
        id = @identities[identity] = CZMQ::Zconfig.load(id_file)
      end

      id.put(path, value)
      id.save(id_file)
      @mtime = File.mtime(@directory)
      self
    end

    def load_ids
      identities = []
      Dir.glob(File.join(@directory, '*.id')) do |id_file|
        identities << File.basename(id_file, '.id')
        if @identities[identities.last]
          if @identities[identities.last].has_changed
            @identities[identities.last] = CZMQ::Zconfig.load(id_file)
          end
        else
          @identities[identities.last] = CZMQ::Zconfig.load(id_file)
        end
      end

      (@identities.keys - identities).each {|identity| @identities.delete(identity) }
      nil
    end
  end

  Keychain.freeze
end
