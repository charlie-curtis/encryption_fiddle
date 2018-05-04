package me.rename.later.exceptions;

import org.apache.commons.lang3.ArrayUtils;

public class EncryptionExceptionHandler extends Exception
{
    //exceptions that are caused by bad input from the client
    private static Class[] clientExceptionClasses = {
        java.security.InvalidKeyException.class
    };
    public static boolean isClientError(Exception ex)
    {
        return ArrayUtils.contains(clientExceptionClasses, ex.getClass());
    }
}
