import me.rename.later.helpers.KeyHelper;
import org.junit.jupiter.api.Test;
import me.rename.later.strategies.AESEncryptionStrategy;
import java.security.Key;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AESEncryptionStrategyTest {

    @Test
    public void testSuccesfullyDecryptsMsg()
    {
        HashMap<String, String> encodedKeys = KeyHelper.generateAESKey();
        String encodedKey = encodedKeys.get(KeyHelper.PRIVATE_KEY);
        Key key = KeyHelper.createAESKeyFromEncodedString(encodedKey);
        AESEncryptionStrategy strat = new AESEncryptionStrategy(key);
        String originalString = "BLA BLA BLA BLA BLA BLA BLA BLA BLA";
        String base64CipherText = strat.encrypt(originalString);
        String decryptedText = strat.decrypt(base64CipherText);
        assertEquals(originalString, decryptedText);
    }
}
