package me.rename.later.strategies;

import me.rename.later.helpers.KeyHelper;
import me.rename.later.interfaces.EncryptionStrategy;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSAEncryptionStrategy implements EncryptionStrategy
{
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private Cipher cipher;

    public RSAEncryptionStrategy(PublicKey publicKey, PrivateKey privateKey) throws GeneralSecurityException
    {
        this.cipher = Cipher.getInstance("RSA");
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public RSAEncryptionStrategy(PublicKey publicKey) throws GeneralSecurityException
    {
        this.cipher = Cipher.getInstance(KeyHelper.CIPHER_RSA);
        this.publicKey = publicKey;
    }

    public RSAEncryptionStrategy(PrivateKey privateKey) throws GeneralSecurityException {
        this.cipher = Cipher.getInstance(KeyHelper.CIPHER_RSA);
        this.privateKey = privateKey;
    }

    /**
     * Encrypt using the public key
     * @param plainText UTF-8 encoded plaintext message
     * @return base64 encoded ciphertext
     * @throws GeneralSecurityException
     */
    public String encrypt(String plainText) throws GeneralSecurityException
    {
        this.cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        byte[] encryptedMessage = this.cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedMessage);
    }

    /**
     * Decrypt using the private key
     * @param cipherText a base64 encoded cipherText
     * @return The unencrypted message. UTF-8 encoded.
     * @throws GeneralSecurityException
     */
    public String decrypt(String cipherText) throws GeneralSecurityException
    {
        byte[] decodedCipherText = Base64.getDecoder().decode(cipherText);
        this.cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        byte[] decryptedMessage = this.cipher.doFinal(decodedCipherText);
        return new String(decryptedMessage);
    }
}
