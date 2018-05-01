package me.rename.later.managers;

import java.security.GeneralSecurityException;
import java.util.Base64;
import me.rename.later.interfaces.EncryptionStrategy;

public class EncryptionManager {

    private EncryptionStrategy encryptionStrategy;

    public EncryptionManager(EncryptionStrategy encryptionStrategy)
    {
        this.encryptionStrategy = encryptionStrategy;
    }

    public byte[] decrypt(byte[] cipherText) throws GeneralSecurityException
    {
        return Base64.getEncoder().encode(
            encryptionStrategy.decrypt(
                Base64.getDecoder().decode(cipherText)));
    }

    public byte[] encrypt(byte[] plainText) throws GeneralSecurityException
    {
        return Base64.getEncoder().encode(
            this.encryptionStrategy.encrypt(
                Base64.getDecoder().decode(plainText)));
    }
}
