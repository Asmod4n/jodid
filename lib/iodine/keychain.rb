module Iodine
  class Keychain
    def initialize(directory = 'identities')
      @directory = directory.dup
      @identities = {}
      @keychain = {}
      @mtime = File.mtime(@directory)
      Dir.glob(File.join(@directory, '*.id')) do |id_file|
        @identities[File.basename(id_file, '.id')] = CZMQ::Zconfig.load(id_file)
      end
    end

    def reload_ids
      @mtime = File.mtime(@directory)
      identities = []
      Dir.glob(File.join(@directory, '*.id')) do |id_file|
        identities << File.basename(id_file, '.id')
        if (id = @identities[identities.last])
          id.reload if id.has_changed
        else
          @identities[identities.last] = CZMQ::Zconfig.load(id_file)
        end
      end

      (@identities.keys - identities).each {|identity| @identities.delete(identity) }
      nil
    end

    def lookup(identity, path)
      reload_ids if File.mtime(@directory) != @mtime

      if (id = @identities[identity])
        id.reload if id.has_changed
        id.resolve(path, nil)
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
      self
    end

    def auth(identity, password)
      salt = Crypto::PwHash::ScryptSalsa208SHA256.salt
      secret_key = Crypto::PwHash.scryptsalsa208sha256(Crypto::Auth::KEYBYTES, password, salt)
      mac = Crypto.auth(password, secret_key)
      store(identity, '/auth/salt', Sodium.bin2hex(salt))
      store(identity, '/auth/mac', Sodium.bin2hex(mac))
      @keychain[identity] = secret_key
      [salt, mac]
    ensure
      password.clear
    end

    def verify(identity, password)
      salt = lookup(identity, '/auth/salt')
      if salt
        mac = lookup(identity, '/auth/mac')
        if mac
          unless (secret_key = @keychain[identity])
            Sodium.hex2bin!(salt, Crypto::PwHash::ScryptSalsa208SHA256::SALTBYTES)
            secret_key = Crypto::PwHash.scryptsalsa208sha256( Crypto::Auth::KEYBYTES,
                                                              password,
                                                              salt)
          end

          Sodium.hex2bin!(mac, Crypto::Auth::BYTES)
          if Crypto::Auth.verify( mac,
                                  password,
                                  secret_key)
            @keychain[identity] ||= secret_key
          end
        end
      end
    ensure
      password.clear
    end

    def logout(identity)
      @keychain.delete(identity)
      true
    end

    def encrypt(identity, password, path, value)
      if (secret_key = verify(identity, password))
        nonce = Crypto::SecretBox.nonce
        ciphertext = Crypto.secretbox(value, nonce, secret_key)
        store(identity, path, Sodium.bin2hex(ciphertext))
        store(identity, "#{path}/nonce", Sodium.bin2hex(nonce))
        [nonce, ciphertext]
      end
    end

    def decrypt(identity, password, path)
      if (secret_key = verify(identity, password))
        ciphertext = lookup(identity, path)
        if ciphertext
          nonce = lookup(identity, "#{path}/nonce")
          if nonce
            Sodium.hex2bin!(ciphertext, ciphertext.bytesize / 2)
            Sodium.hex2bin!(nonce, Crypto::SecretBox::NONCEBYTES)
            Crypto::SecretBox.open!(  ciphertext,
                                      nonce,
                                      secret_key,
                                      Encoding.default_external)
          end
        end
      end
    end

    def encrypt!(identity, password, path, value)
      if (secret_key = verify(identity, password))
        nonce = Crypto::SecretBox.nonce
        Crypto.secretbox!(value, nonce, secret_key)
        store(identity, path, Sodium.bin2hex(value))
        store(identity, "#{path}/nonce", Sodium.bin2hex(nonce))
        [nonce, value.force_encoding(Encoding::ASCII_8BIT)]
      end
    end
  end

  Keychain.freeze
end
