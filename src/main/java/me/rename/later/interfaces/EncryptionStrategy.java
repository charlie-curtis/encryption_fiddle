package me.rename.later.interfaces;

import java.security.GeneralSecurityException;

public interface EncryptionStrategy
{
    byte[] encrypt(byte[] plainText) throws GeneralSecurityException;
    byte[] decrypt(byte[] cipherText) throws GeneralSecurityException;
}
