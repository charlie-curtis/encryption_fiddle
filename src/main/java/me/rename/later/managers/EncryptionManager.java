package me.rename.later.managers;

import me.rename.later.interfaces.EncryptionStrategy;

public class EncryptionManager {

    private byte[] encryptionKey;
    private EncryptionStrategy encryptionStrategy;

    public EncryptionManager(EncryptionStrategy encryptionStrategy, byte[] encryptionKey)
    {
        this.encryptionStrategy = encryptionStrategy;
        this.encryptionKey = encryptionKey;
    }

    public byte[] decrypt(byte[] cipherText)
    {
        return this.encryptionStrategy.decrypt(cipherText);
    }

    public byte[] encrypt(byte[] plainText)
    {
        return this.encryptionStrategy.encrypt(plainText);
    }
}
