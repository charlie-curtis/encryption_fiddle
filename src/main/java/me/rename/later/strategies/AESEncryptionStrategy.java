package me.rename.later.strategies;

import me.rename.later.interfaces.EncryptionStrategy;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.util.Base64;

public class AESEncryptionStrategy implements EncryptionStrategy
{

    private Cipher cipher;
    private Key key;

    /**
     * Sets up the encryption algorithm to use AES encryption
     * @param key must be a valid AES encryption size. 128/192/256 bits
     */
    public AESEncryptionStrategy(Key key)
    {
        try {
            this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            this.key = key;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String encrypt(String plainText)
    {
        try {
            this.cipher.init(Cipher.ENCRYPT_MODE, this.key);
            IvParameterSpec ivParameterSpec = cipher.getParameters().getParameterSpec(IvParameterSpec.class);
            String ivSpec = Base64.getEncoder().encodeToString(ivParameterSpec.getIV());
            String message = Base64.getEncoder().encodeToString(this.cipher.doFinal(plainText.getBytes()));
            //Put the IV Spec as part of the message so that the decryption can detect it
            return ivSpec + ":" + message;
        } catch (Exception e) {
            //Throw a 500 for now
            throw new RuntimeException(e);
        }
    }

    /**
     *
     * @param cipherText A base 64 encoded string. The IV spec is appended
     *                   to the front of the original message text.
     * @return A UTF-8 plaintext string
     */
    public String decrypt(String cipherText)
    {
        try {
            String[] cipherTextParts = cipherText.split(":");
            byte[] ivSpec = Base64.getDecoder().decode(cipherTextParts[0]);
            IvParameterSpec ivSpecParam = new IvParameterSpec(ivSpec);
            byte[] encryptedMessage = Base64.getDecoder().decode(cipherTextParts[1]);
            this.cipher.init(Cipher.DECRYPT_MODE, this.key, ivSpecParam);
            byte[] decryptedMessage = this.cipher.doFinal(encryptedMessage);
            return new String(decryptedMessage);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
