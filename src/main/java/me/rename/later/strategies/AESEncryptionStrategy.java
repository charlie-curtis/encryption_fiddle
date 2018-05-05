package me.rename.later.strategies;

import me.rename.later.exceptions.EncryptionFiddleException;
import me.rename.later.interfaces.EncryptionStrategy;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

public class AESEncryptionStrategy implements EncryptionStrategy
{

    private Cipher cipher;
    private Key key;

    /**
     * Sets up the encryption algorithm to use AES encryption
     * @param key must be a valid AES encryption size. 128/192/256 bits
     */
    public AESEncryptionStrategy(Key key) throws NoSuchAlgorithmException, NoSuchPaddingException
    {
        this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        this.key = key;
    }

    public String encrypt(String plainText) throws InvalidKeyException,
        InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
        InvalidParameterSpecException
    {
        this.cipher.init(Cipher.ENCRYPT_MODE, this.key);
        IvParameterSpec ivParameterSpec = cipher.getParameters().getParameterSpec(IvParameterSpec.class);
        String ivSpec = Base64.getEncoder().encodeToString(ivParameterSpec.getIV());
        String message = Base64.getEncoder().encodeToString(this.cipher.doFinal(plainText.getBytes()));
        //Put the IV Spec as part of the message so that the decryption can detect it
        return ivSpec + ":" + message;
    }

    /**
     *
     * @param cipherText A base 64 encoded string. The IV spec is appended
     *                   to the front of the original message text.
     * @return A UTF-8 plaintext string
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidParameterSpecException
     */
    public String decrypt(String cipherText) throws InvalidKeyException,
        InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        String[] cipherTextParts = cipherText.split(":");
        if (cipherTextParts.length != 2) {
            throw new EncryptionFiddleException("Invalid key format. IV Spec couldn't be determined");
        }
        byte[] ivSpec = Base64.getDecoder().decode(cipherTextParts[0]);
        IvParameterSpec ivSpecParam = new IvParameterSpec(ivSpec);
        byte[] encryptedMessage = Base64.getDecoder().decode(cipherTextParts[1]);
        this.cipher.init(Cipher.DECRYPT_MODE, this.key, ivSpecParam);
        byte[] decryptedMessage = this.cipher.doFinal(encryptedMessage);
        return new String(decryptedMessage);
    }
}
