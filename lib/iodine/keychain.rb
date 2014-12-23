require 'base64'

module Iodine
  class Keychain
    def initialize(directory = 'identities')
      FileUtils.mkdir_p(directory)
      @directory = directory.dup
      @mtime = File.mtime(@directory)
      @identities = {}
      @keychain = {}
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

      (@identities.keys - identities).each do |identity|
        @identities.delete(identity)
        @keychain.delete(identity)
      end
      nil
    end

    def lookup(identity, path)
      reload_ids if File.mtime(@directory) != @mtime

      if (id = @identities[identity])
        id.reload if id.has_changed
        if (encoding = id.resolve("#{path}/encoding", nil))
          value = id.resolve(path, nil)
          Sodium::Utils.hex2bin(value).force_encoding(encoding) if value
        else
          id.resolve(path, nil)
        end
      end
    end

    def store(identity, path, value)
      id_file = File.join(@directory, "#{identity}.id")
      unless File.dirname(id_file) == @directory
        fail ArgumentError, "identity=#{identity} contains illegal characters", caller
      end

      unless (id = @identities[identity])
        FileUtils.touch id_file
        id = @identities[identity] = CZMQ::Zconfig.load(id_file)
      end

      data = String(value)
      if data.ascii_only?
        id.put(path, data)
      else
        id.put(path, Sodium::Utils.bin2hex(data))
        id.put("#{path}/encoding", data.encoding.to_s)
      end
      id.save(id_file)
      true
    end

    def store_public_key(identity, public_key)
      case public_key.bytesize
      when 32
        store(identity, '/public_key', public_key)
      when 40
        store(identity, '/public_key', Libzmq.z85_decode(public_key))
      when 44
        store(identity, '/public_key', Base64.urlsafe_decode64(public_key))
      when 64
        store(identity, '/public_key', Sodium::Utils.hex2bin(public_key))
      else
        raise ArgumentError, "public_key=#{public_key} is not in binary, z85, Base64 or hex encoding", caller
      end
    end

    def auth(identity, password)
      salt = Crypto::PwHash::ScryptSalsa208SHA256.salt
      secret_key = Crypto::PwHash.scryptsalsa208sha256( Crypto::Auth::KEYBYTES,
                                                        password,
                                                        salt)
      public_key = Crypto::ScalarMult.base(secret_key)
      mac = Crypto.auth(password, secret_key)
      store(identity, '/auth', salt << mac)
      store_public_key(identity, public_key)
      @keychain[identity] = secret_key
      Libzmq.z85_encode public_key
    ensure
      password.clear
    end

    def verify(identity, password)
      if (auth = lookup(identity, '/auth'))
        unless (secret_key = @keychain[identity])
          secret_key = Crypto::PwHash.scryptsalsa208sha256(
            Crypto::Auth::KEYBYTES,
            password,
            auth[0, Crypto::PwHash::ScryptSalsa208SHA256::SALTBYTES])
        end

        if Crypto::Auth.verify(
          auth[Crypto::PwHash::ScryptSalsa208SHA256::SALTBYTES, Crypto::Auth::BYTES],
          password,
          secret_key)

          @keychain[identity] = secret_key
        end
      end
    ensure
      password.clear
    end

    def logout(identity, password)
      if verify(identity, password)
        @keychain.delete(identity)
        true
      end
    end

    def encrypt(identity, password, value)
      if (secret_key = verify(identity, password))
        data = String(value)
        nonce = Crypto::SecretBox.nonce
        Crypto.secretbox(data, nonce, secret_key) << nonce
      end
    end

    def decrypt(identity, password, ciphertext, encoding = Encoding.default_external)
      if (secret_key = verify(identity, password))
        Crypto::SecretBox.open( ciphertext[0...-Crypto::SecretBox::NONCEBYTES],
                                ciphertext[-Crypto::SecretBox::NONCEBYTES..-1],
                                secret_key,
                                encoding)
      end
    end

    def encrypt!(identity, password, value)
      if (secret_key = verify(identity, password))
        data = String(value)
        nonce = Crypto::SecretBox.nonce
        Crypto.secretbox!(data, nonce, secret_key) << nonce
      end
    end

    def decrypt!(identity, password, ciphertext, encoding = Encoding.default_external)
      if (secret_key = verify(identity, password))
        nonce = ciphertext.slice!(-Crypto::SecretBox::NONCEBYTES..-1)
        Crypto::SecretBox.open!(ciphertext,
                                nonce,
                                secret_key,
                                encoding)
      end
    end

    def encrypt_for(identity, password, value, recipient)
      if (secret_key = verify(identity, password))
        if (public_key = lookup(recipient, '/public_key'))
          data = String(value)
          nonce = Crypto::Box.nonce
          Crypto.box(data, nonce, public_key, secret_key) << nonce
        end
      end
    end

    def decrypt_from(identity, password, ciphertext, sender, encoding = Encoding.default_external)
      if (secret_key = verify(identity, password))
        if (public_key = lookup(sender, '/public_key'))
          Crypto::Box.open( ciphertext[0...-Crypto::Box::NONCEBYTES],
                            ciphertext[-Crypto::Box::NONCEBYTES..-1],
                            public_key,
                            secret_key,
                            encoding)
        end
      end
    end

    def encrypt_for!(identity, password, value, recipient)
      if (secret_key = verify(identity, password))
        if (public_key = lookup(recipient, '/public_key'))
          data = String(value)
          nonce = Crypto::Box.nonce
          Crypto.box!(data, nonce, public_key, secret_key) << nonce
        end
      end
    end

    def decrypt_from!(identity, password, ciphertext, sender, encoding = Encoding.default_external)
      if (secret_key = verify(identity, password))
        if (public_key = lookup(sender, '/public_key'))
          nonce = ciphertext.slice!(-Crypto::Box::NONCEBYTES..-1)
          Crypto::Box.open!(ciphertext,
                            nonce
                            public_key,
                            secret_key,
                            encoding)
        end
      end
    end
  end

  Keychain.freeze
end
