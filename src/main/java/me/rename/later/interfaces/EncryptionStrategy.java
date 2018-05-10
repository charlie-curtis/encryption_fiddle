package me.rename.later.interfaces;

public interface EncryptionStrategy
{
    String encrypt(String plainText);
    String decrypt(String cipherText);
}
