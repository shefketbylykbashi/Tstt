package com.example;

import org.bouncycastle.pqc.crypto.frodo.*;
import org.bouncycastle.pqc.crypto.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.util.encoders.Hex;
import java.security.SecureRandom;

public class FrodoKEM {

    public void runDemo() {
        try {
            FrodoParameters params = FrodoParameters.frodokem640aes;
            System.out.println("=== FrodoKEM Demonstration ===");
            System.out.println("Using parameter set: " + params.getName());

            long startKeyGen = System.nanoTime();
            FrodoKeyPairGenerator keyGen = new FrodoKeyPairGenerator();
            keyGen.init(new FrodoKeyGenerationParameters(new SecureRandom(), params));
            AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();
            long endKeyGen = System.nanoTime();

            FrodoPublicKeyParameters publicKey = (FrodoPublicKeyParameters) keyPair.getPublic();
            FrodoPrivateKeyParameters privateKey = (FrodoPrivateKeyParameters) keyPair.getPrivate();

            System.out.printf("Key generation took: %d ms%n", (endKeyGen - startKeyGen) / 1_000_000);
            System.out.println("Public key length: " + publicKey.getEncoded().length + " bytes");
            System.out.println("Private key length: " + privateKey.getEncoded().length + " bytes");

            FileUtils.saveBytes("output/public.key", publicKey.getEncoded());
            FileUtils.saveBytes("output/private.key", privateKey.getEncoded());

            long startEncap = System.nanoTime();
            FrodoKEMGenerator encapsulator = new FrodoKEMGenerator(new SecureRandom());
            SecretWithEncapsulation secretEnc = encapsulator.generateEncapsulated(publicKey);
            long endEncap = System.nanoTime();

            byte[] sharedEnc = secretEnc.getSecret();
            byte[] ciphertext = secretEnc.getEncapsulation();

            System.out.printf("Encapsulation took: %d ms%n", (endEncap - startEncap) / 1_000_000);
            System.out.println("Ciphertext length: " + ciphertext.length + " bytes");
            FileUtils.saveBytes("output/ciphertext.bin", ciphertext);

            long startDecap = System.nanoTime();
            FrodoKEMExtractor extractor = new FrodoKEMExtractor(privateKey);
            byte[] sharedDec = extractor.extractSecret(ciphertext);
            long endDecap = System.nanoTime();

            System.out.printf("Decapsulation took: %d ms%n", (endDecap - startDecap) / 1_000_000);

            System.out.println("\nShared key (encapsulator): " + Hex.toHexString(sharedEnc));
            System.out.println("Shared key (decapsulator): " + Hex.toHexString(sharedDec));

            if (constantTimeEquals(sharedEnc, sharedDec))
                System.out.println("Keys match!");
            else
                System.out.println("Keys differ!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
