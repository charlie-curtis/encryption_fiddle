package me.rename.later.managers;

import me.rename.later.interfaces.EncryptionStrategy;

public class EncryptionManager {

    private EncryptionStrategy encryptionStrategy;

    public EncryptionManager(EncryptionStrategy encryptionStrategy)
    {
        this.encryptionStrategy = encryptionStrategy;
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
