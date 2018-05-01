package me.rename.later.exceptions;

import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.NoSuchPaddingException;
import javax.ws.rs.core.Response;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class EncryptionExceptionHandler extends Exception {

    //exceptions that are caused by bad input from the client
    private static Class[] clientExceptionClasses = {
        //NoSuchAlgorithmException.class,
        //NoSuchPaddingException.class,
        //InvalidAlgorithmParameterException.class
        java.security.InvalidKeyException.class
    };
    public static boolean isClientError(Exception ex)
    {
        System.out.println("Class I got was " + ex.getClass());
        return ArrayUtils.contains(clientExceptionClasses, ex.getClass());
    }
}
