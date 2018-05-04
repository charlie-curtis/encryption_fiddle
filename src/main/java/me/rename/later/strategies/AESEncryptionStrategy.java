package me.rename.later.strategies;

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

public class AESEncryptionStrategy implements EncryptionStrategy
{

    private Cipher cipher;
    private Key key;
    private IvParameterSpec ivSpec;

    /**
     * Sets up the encryption algorithm to use AES encryption
     * @param key must be a valid AES encryption size. 128/192/256 bits
     */
    public AESEncryptionStrategy(Key key) throws NoSuchAlgorithmException, NoSuchPaddingException
    {
        this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        this.key = key;
        this.initializeIvSpec();
    }

    private void initializeIvSpec()
    {
        //TODO redesign the IV spec
        byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        this.ivSpec = new IvParameterSpec(iv);
    }

    public byte[] encrypt(byte[] plainText) throws InvalidKeyException,
        InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        this.cipher.init(Cipher.ENCRYPT_MODE, this.key, ivSpec);
        return this.cipher.doFinal(plainText);
    }

    public byte[] decrypt(byte[] cipherText) throws InvalidKeyException,
        InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        this.cipher.init(Cipher.DECRYPT_MODE, this.key, this.ivSpec);
        return this.cipher.doFinal(cipherText);
    }
}
