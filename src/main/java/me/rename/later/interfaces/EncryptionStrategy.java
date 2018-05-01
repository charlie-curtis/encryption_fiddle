package me.rename.later.interfaces;

public interface EncryptionStrategy {
    public byte[] encrypt(byte[] plainText);
    public byte[] decrypt(byte[] cipherText);
}
