import java.io.*;
import java.net.*;
import java.math.*;
import java.security.*;
import java.security.spec.*;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.*;

public class DiffieHellman {
	private boolean DEBUG = true;

	private ObjectInputStream cipherIn; // secure channels
	private ObjectOutputStream cipherOut;
	private Record record;
	private SecretKey sessionKey;
	byte[] initializationVector;

	DiffieHellman() {

	}

	/*
	 * 
	 * Diffie-Hellman Parameters for 1024 bits Modulus (1024-bit prime modulus
	 * P, base G)
	 */
	private final byte SKIP_1024_MODULUS_BYTES[] = { (byte) 0xF4, (byte) 0x88,
			(byte) 0xFD, (byte) 0x58, (byte) 0x4E, (byte) 0x49, (byte) 0xDB,
			(byte) 0xCD, (byte) 0x20, (byte) 0xB4, (byte) 0x9D, (byte) 0xE4,
			(byte) 0x91, (byte) 0x07, (byte) 0x36, (byte) 0x6B, (byte) 0x33,
			(byte) 0x6C, (byte) 0x38, (byte) 0x0D, (byte) 0x45, (byte) 0x1D,
			(byte) 0x0F, (byte) 0x7C, (byte) 0x88, (byte) 0xB3, (byte) 0x1C,
			(byte) 0x7C, (byte) 0x5B, (byte) 0x2D, (byte) 0x8E, (byte) 0xF6,
			(byte) 0xF3, (byte) 0xC9, (byte) 0x23, (byte) 0xC0, (byte) 0x43,
			(byte) 0xF0, (byte) 0xA5, (byte) 0x5B, (byte) 0x18, (byte) 0x8D,
			(byte) 0x8E, (byte) 0xBB, (byte) 0x55, (byte) 0x8C, (byte) 0xB8,
			(byte) 0x5D, (byte) 0x38, (byte) 0xD3, (byte) 0x34, (byte) 0xFD,
			(byte) 0x7C, (byte) 0x17, (byte) 0x57, (byte) 0x43, (byte) 0xA3,
			(byte) 0x1D, (byte) 0x18, (byte) 0x6C, (byte) 0xDE, (byte) 0x33,
			(byte) 0x21, (byte) 0x2C, (byte) 0xB5, (byte) 0x2A, (byte) 0xFF,
			(byte) 0x3C, (byte) 0xE1, (byte) 0xB1, (byte) 0x29, (byte) 0x40,
			(byte) 0x18, (byte) 0x11, (byte) 0x8D, (byte) 0x7C, (byte) 0x84,
			(byte) 0xA7, (byte) 0x0A, (byte) 0x72, (byte) 0xD6, (byte) 0x86,
			(byte) 0xC4, (byte) 0x03, (byte) 0x19, (byte) 0xC8, (byte) 0x07,
			(byte) 0x29, (byte) 0x7A, (byte) 0xCA, (byte) 0x95, (byte) 0x0C,
			(byte) 0xD9, (byte) 0x96, (byte) 0x9F, (byte) 0xAB, (byte) 0xD0,
			(byte) 0x0A, (byte) 0x50, (byte) 0x9B, (byte) 0x02, (byte) 0x46,
			(byte) 0xD3, (byte) 0x08, (byte) 0x3D, (byte) 0x66, (byte) 0xA4,
			(byte) 0x5D, (byte) 0x41, (byte) 0x9F, (byte) 0x9C, (byte) 0x7C,
			(byte) 0xBD, (byte) 0x89, (byte) 0x4B, (byte) 0x22, (byte) 0x19,
			(byte) 0x26, (byte) 0xBA, (byte) 0xAB, (byte) 0xA2, (byte) 0x5E,
			(byte) 0xC3, (byte) 0x55, (byte) 0xE9, (byte) 0x2F, (byte) 0x78,
			(byte) 0xC7 };

	private final BigInteger P_MODULUS = new BigInteger(1,
			SKIP_1024_MODULUS_BYTES);
	private final BigInteger G_BASE = BigInteger.valueOf(2);
	private final DHParameterSpec PARAMETER_SPEC = new DHParameterSpec(
			P_MODULUS, G_BASE);



	public void createNewKey(String username, boolean client,ObjectInputStream in, ObjectOutputStream out) {
		try {
			System.out.println("Initiating the key agreement protocol ...");
			System.out.println("Generating a Diffie-Hellman KeyPair...");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
			kpg.initialize(PARAMETER_SPEC);
			KeyPair keyPair = kpg.genKeyPair();

			Message syn;
			KeyAgreement ka = null;
			initializationVector = null;
			if (client) {
				System.out.println("Receiving the server's public key ...");
				syn = (Message) in.readObject();
				byte[] keyBytes = syn.getEncondedPublicKey();
				KeyFactory kf = KeyFactory.getInstance("DH");
				X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(keyBytes);
				PublicKey serverPublicKey = kf.generatePublic(x509Spec);

				System.out.println("Sending my public key ...");
				keyBytes = keyPair.getPublic().getEncoded();
				syn.setEncondedPublicKey(keyBytes);
				out.writeObject(syn);
				out.reset();
				out.flush();
				System.out.println("Performing the KeyAgreement...");
				ka = KeyAgreement.getInstance("DH");
				ka.init(keyPair.getPrivate());
				ka.doPhase(serverPublicKey, true);

				System.out.println("Receiving the initialization vector ...");
				initializationVector = new byte[8];
				syn = (Message) in.readObject();
				initializationVector = syn.getInitializationVector();
			} else {
				syn=new Message(username, "NEW");
				System.out.println("Sending the server public key to client: "+ username);
				byte[] keyBytes = keyPair.getPublic().getEncoded();
				syn.setEncondedPublicKey(keyBytes);
				out.writeObject(syn);
				out.reset();
				out.flush();

				System.out.println("Receiving client's public key: " + username);
				syn = (Message) in.readObject();
				keyBytes = syn.getEncondedPublicKey();
				KeyFactory kf = KeyFactory.getInstance("DH");
				X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(keyBytes);
				PublicKey clientPublicKey = kf.generatePublic(x509Spec);

				System.out.println("Performing the KeyAgreement...");
				ka = KeyAgreement.getInstance("DH");
				ka.init(keyPair.getPrivate());
				ka.doPhase(clientPublicKey, true);
				
				System.out.println("Create and send the IVParameterSpec to the client: "+ username);
				initializationVector = new byte[8];
				SecureRandom random = new SecureRandom();
				random.nextBytes(initializationVector);
				syn.setInitializationVector(initializationVector);
				out.writeObject(syn);
				out.reset();
				out.flush();
			}

			System.out.println("Creating a session key ...");
			byte[] sessionKeyBytes = ka.generateSecret();
			SecretKeyFactory skf = SecretKeyFactory.getInstance("TripleDES");
			DESedeKeySpec tripleDesSpec = new DESedeKeySpec(sessionKeyBytes);
			sessionKey = skf.generateSecret(tripleDesSpec);

			System.out.println("Creating the CipherStreams to be used with server...");

			Cipher decrypter = Cipher.getInstance("TripleDES/CFB8/NoPadding");
			Cipher encrypter = Cipher.getInstance("TripleDES/CFB8/NoPadding");

			IvParameterSpec spec = new IvParameterSpec(initializationVector);

			encrypter.init(Cipher.ENCRYPT_MODE, sessionKey, spec);
			decrypter.init(Cipher.DECRYPT_MODE, sessionKey, spec);

			cipherOut = new ObjectOutputStream(new CipherOutputStream(out,encrypter));
			cipherOut.flush();
			cipherIn = new ObjectInputStream(new CipherInputStream(in,	decrypter));

			if (!client){
				// add a new table entry for future connections
				SessionKey key = new SessionKey(initializationVector,sessionKey);
				record = new Record(username, key, System.currentTimeMillis());
			}

		} catch (Exception e) {
			if (DEBUG)
				e.printStackTrace();
		}

	}

	public ObjectInputStream getCipherIn() {
		return cipherIn;
	}

	public void setCipherIn(ObjectInputStream cipherIn) {
		this.cipherIn = cipherIn;
	}

	public ObjectOutputStream getCipherOut() {
		return cipherOut;
	}

	public void setCipherOut(ObjectOutputStream cipherOut) {
		this.cipherOut = cipherOut;
	}

	public Record getRecord() {
		return record;
	}

	public SecretKey getSessionKey() {
		return sessionKey;
	}

	public byte[] getInitializationVector() {
		return initializationVector;
	}
	

}
