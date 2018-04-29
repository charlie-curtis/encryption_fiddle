package me.rename.later.managers;

public class EncryptionManager {

    private String cipherText;
    private String plainText;
    private String encryptionKey;

    public EncryptionManager(String plainText, String encryptionKey)
    {
        this.plainText = plainText;
        this.encryptionKey = encryptionKey;
    }
}
