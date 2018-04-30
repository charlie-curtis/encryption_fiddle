import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import me.rename.later.strategies.AESEncryptionStrategy;

public class AESEncryptionStrategyTest {


    @Test
    public void testSuccesfullyDecryptsMsg()
    {
        String key = "ABCDEFGHIJKLMNOPQRSTUVWX";
        AESEncryptionStrategy strat = new AESEncryptionStrategy(key.getBytes());
        String originalString = "BLA BLA BLA BLA BLA BLA BLA BLA BLA";
        byte[] plainText = originalString.getBytes();
        byte[] cipherText = strat.encrypt(plainText);
        byte[] decryptedText = strat.decrypt(cipherText);
        String decryptedString = new String(decryptedText);
        assertEquals(originalString, decryptedString);
    }
}