import static org.junit.jupiter.api.Assertions.*;

import me.rename.later.strategies.RSAEncryptionStrategy;
import org.junit.jupiter.api.Test;
import me.rename.later.strategies.AESEncryptionStrategy;

public class RSAEncryptionStrategyTest {

    @Test
    public void testSuccesfullyDecryptsMsg() throws Exception
    {
        RSAEncryptionStrategy strat = new RSAEncryptionStrategy();
        String originalString = "BLA BLA BLA BLA BLA BLA BLA BLA BLA";
        byte[] plainText = originalString.getBytes();
        byte[] cipherText = strat.encrypt(plainText);
        byte[] decryptedText = strat.decrypt(cipherText);
        String decryptedString = new String(decryptedText);
        assertEquals(originalString, decryptedString);
    }
}
