import me.rename.later.helpers.KeyHelper;
import me.rename.later.strategies.RSAEncryptionStrategy;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RSAEncryptionStrategyTest {

    @Test
    public void testSuccesfullyDecryptsMsg()
    {
        HashMap<String, String> keys = KeyHelper.generateRSAKeys();
        String base64PublicKey = keys.get(KeyHelper.PUBLIC_KEY);
        String base64PrivateKey = keys.get(KeyHelper.PRIVATE_KEY);
        PublicKey publicKey = KeyHelper.createRSAPublicKeyFromBase64EncodedString(base64PublicKey);
        PrivateKey privateKey = KeyHelper.createRSAPrivateKeyFromBase64EncodedString(base64PrivateKey);
        RSAEncryptionStrategy strat = new RSAEncryptionStrategy(publicKey, privateKey);
        String originalString = "BLA BLA BLA BLA BLA BLA BLA BLA BLA";
        String cipherText = strat.encrypt(originalString);
        String decryptedText = strat.decrypt(cipherText);
        assertEquals(originalString, decryptedText);
    }
}
