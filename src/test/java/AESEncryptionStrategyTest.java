import me.rename.later.helpers.KeyHelper;
import org.junit.jupiter.api.Test;
import me.rename.later.strategies.AESEncryptionStrategy;
import java.security.Key;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AESEncryptionStrategyTest {

    @Test
    public void testSuccesfullyDecryptsMsg() throws Exception
    {
        HashMap<String, String> encodedKeys = KeyHelper.generateAESKey();
        String encodedKey = encodedKeys.get(KeyHelper.PRIVATE_KEY);
        Key key = KeyHelper.createAESKeyFromBase64EncodedString(encodedKey);
        AESEncryptionStrategy strat = new AESEncryptionStrategy(key);
        String originalString = "BLA BLA BLA BLA BLA BLA BLA BLA BLA";
        byte[] plainText = originalString.getBytes();
        byte[] cipherText = strat.encrypt(plainText);
        byte[] decryptedText = strat.decrypt(cipherText);
        String decryptedString = new String(decryptedText);
        assertEquals(originalString, decryptedString);
    }
}
