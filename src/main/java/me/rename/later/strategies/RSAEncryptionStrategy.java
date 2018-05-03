package me.rename.later.strategies;

import me.rename.later.interfaces.EncryptionStrategy;

import javax.crypto.Cipher;
import java.security.*;

public class RSAEncryptionStrategy implements EncryptionStrategy
{
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private Cipher cipher;

    public RSAEncryptionStrategy(PublicKey publicKey, PrivateKey privateKey) throws GeneralSecurityException
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.cipher = Cipher.getInstance("RSA");
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    /**
     * Encrypt using the public key
     * @param plainText
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] encrypt(byte[] plainText) throws GeneralSecurityException
    {
        this.cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        return this.cipher.doFinal(plainText);
    }

    /**
     * Decrypt using the private key
     * @param cipherText
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] decrypt(byte[] cipherText) throws GeneralSecurityException
    {
        this.cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        return this.cipher.doFinal(cipherText);
    }
}
