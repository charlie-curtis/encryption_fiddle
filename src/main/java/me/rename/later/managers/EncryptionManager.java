package me.rename.later.managers;

import java.security.GeneralSecurityException;
import me.rename.later.interfaces.EncryptionStrategy;

public class EncryptionManager {

    private EncryptionStrategy encryptionStrategy;

    public EncryptionManager(EncryptionStrategy encryptionStrategy)
    {
        this.encryptionStrategy = encryptionStrategy;
    }

    public String decrypt(String cipherText) throws GeneralSecurityException
    {
        return this.encryptionStrategy.decrypt(cipherText);
    }

    public String encrypt(String plainText) throws GeneralSecurityException
    {
        return this.encryptionStrategy.encrypt(plainText);
    }
}
