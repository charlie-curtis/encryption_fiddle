package me.rename.later.exceptions;

import org.apache.commons.lang3.ArrayUtils;

public class EncryptionExceptionHandler extends Exception {

    //exceptions that are caused by bad input from the client
    private static Class[] clientExceptionClasses = {
        java.security.InvalidKeyException.class
    };
    public static boolean isClientError(Exception ex)
    {
        System.out.println("Class I got was " + ex.getClass());
        return ArrayUtils.contains(clientExceptionClasses, ex.getClass());
    }
}
