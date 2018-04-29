package me.rename.later.strategies;

import me.rename.later.interfaces.EncryptionStrategy;
import me.rename.later.exceptions.CryptoExceptionWrapper;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Key;

public class AESEncryptionStrategy implements EncryptionStrategy
{

    private Cipher cipher;
    private Key key;
    private IvParameterSpec ivSpec;

    public AESEncryptionStrategy(byte[] key)
    {
        try {
            this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (GeneralSecurityException e) {
            //TODO log error, return 400
            e.printStackTrace();
            System.exit(1);
        }
        this.key = new SecretKeySpec(key, "AES");
        //TODO redesign the IV spec
        byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        this.ivSpec = new IvParameterSpec(iv);
    }

    public byte[] encrypt(byte[] plainText)
    {
        try {
            this.cipher.init(Cipher.ENCRYPT_MODE, this.key, ivSpec);
            return this.cipher.doFinal(plainText);
        } catch (GeneralSecurityException e) {
            //TODO log error, return 400
            e.printStackTrace();
            System.exit(1);
        }
        return new byte[0];
    }

    public byte[] decrypt(byte[] cipherText)
    {
        try {
            this.cipher.init(Cipher.DECRYPT_MODE, this.key, this.ivSpec);
            return this.cipher.doFinal(cipherText);
        } catch (GeneralSecurityException e) {
            //TODO log error, return 400
            e.printStackTrace();
            System.exit(1);
        }
        return new byte[0];
    }
}
