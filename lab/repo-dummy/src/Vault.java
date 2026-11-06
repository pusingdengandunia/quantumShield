// Dummy application code: the Q-Shield code scanner should flag this file.
import java.security.KeyPairGenerator;

class Vault {
    KeyPairGenerator create() throws Exception {
        return KeyPairGenerator.getInstance("RSA");
    }
}
