package me.rename.later.interfaces;

import java.security.GeneralSecurityException;

public interface EncryptionStrategy
{
    String encrypt(String plainText) throws GeneralSecurityException;
    String decrypt(String cipherText) throws GeneralSecurityException;
}
