package me.rename.later.managers;

import me.rename.later.interfaces.EncryptionStrategy;

public class EncryptionManager {

    private EncryptionStrategy encryptionStrategy;

    public EncryptionManager(EncryptionStrategy encryptionStrategy)
    {
        this.encryptionStrategy = encryptionStrategy;
    }

    public String decrypt(String cipherText)
    {
        return this.encryptionStrategy.decrypt(cipherText);
    }

    public String encrypt(String plainText)
    {
        return this.encryptionStrategy.encrypt(plainText);
    }
}
