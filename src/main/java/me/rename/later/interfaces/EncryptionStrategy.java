package me.rename.later.interfaces;

import java.security.GeneralSecurityException;

public interface EncryptionStrategy {
    public byte[] encrypt(byte[] plainText) throws GeneralSecurityException;
    public byte[] decrypt(byte[] cipherText) throws GeneralSecurityException;
}
