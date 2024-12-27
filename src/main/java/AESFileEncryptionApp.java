import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class AESFileEncryptionApp {

    private static final String ALGORITHM = "AES";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\n--- MENU ---");
            System.out.println("1. Encriptar");
            System.out.println("2. Desencriptar");
            System.out.println("3. Sortir");
            System.out.print("Seleccioneu una opcio: ");

            int option = scanner.nextInt();
            scanner.nextLine();

            switch (option) {
                case 1:
                    // Encriptar
                    System.out.print("Introduiu el missatge a encriptar: ");
                    String messageToEncrypt = scanner.nextLine();
                    System.out.print("Introduiu la contrasenya (16 caracters): ");
                    String encryptionKey = scanner.nextLine();

                    if (encryptionKey.length() != 16) {
                        System.out.println("La contrasenya ha de tenir exactament 16 caracters.");
                        break;
                    }

                    try {
                        String encryptedMessage = encrypt(messageToEncrypt, encryptionKey);
                        System.out.println("Missatge encriptat: " + encryptedMessage);
                    } catch (Exception e) {
                        System.out.println("Error durant l'encriptacio: " + e.getMessage());
                    }
                    break;

                case 2:
                    // Desencriptar
                    System.out.print("Introduiu el missatge encriptat: ");
                    String messageToDecrypt = scanner.nextLine();
                    System.out.print("Introduiu la contrasenya (16 caracters): ");
                    String decryptionKey = scanner.nextLine();

                    if (decryptionKey.length() != 16) {
                        System.out.println("La contrasenya ha de tenir exactament 16 caracters.");
                        break;
                    }

                    try {
                        String decryptedMessage = decrypt(messageToDecrypt, decryptionKey);
                        System.out.println("Missatge desencriptat: " + decryptedMessage);
                    } catch (Exception e) {
                        System.out.println("Error durant la desencriptacio: " + e.getMessage());
                    }
                    break;

                case 3:
                    // Sortir
                    System.out.println("Sortint de l'aplicacio. Adeu!");
                    scanner.close();
                    return;

                default:
                    System.out.println("Opcio no valida. Si us plau, trieu una opcio entre 1 i 3.");
            }
        }
    }

    private static String encrypt(String data, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String data, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(decryptedBytes);
    }
}
