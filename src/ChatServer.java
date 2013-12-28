import java.io.*;
import java.net.*;
import java.math.*;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.*;
import javax.crypto.spec.*;

public class ChatServer{
	
	private static final String TABLE_FILE = "../data/LookupTable.ser";
	private static final String ENCRYPTED_TABLE_FILE = "../data/LookupTable_DES";
	
	private static List<ObjectInputStream> cipherInPool = new ArrayList<ObjectInputStream>();				    //Secure channels
	private static List<ObjectOutputStream> cipherOutPool = new ArrayList<ObjectOutputStream>();
			
	private static List <ObjectInputStream> objectInPool = new ArrayList<ObjectInputStream>();				//Insecure channels
	private static List <ObjectOutputStream> objectOutPool = new ArrayList<ObjectOutputStream>();
	
	private static List <String> onlineUsers= new ArrayList<String>();
	
	private static Boolean DEBUG=false;
	
	private static LookupTable table;
	
	/*
	 * 
	 * Diffie-Hellman Parameters for 1024 bits Modulus (1024-bit prime modulus P, base G)
	 * 
	 */
	private static final byte SKIP_1024_MODULUS_BYTES[] = {
	    (byte)0xF4, (byte)0x88, (byte)0xFD, (byte)0x58,
	    (byte)0x4E, (byte)0x49, (byte)0xDB, (byte)0xCD,
	    (byte)0x20, (byte)0xB4, (byte)0x9D, (byte)0xE4,
	    (byte)0x91, (byte)0x07, (byte)0x36, (byte)0x6B,
	    (byte)0x33, (byte)0x6C, (byte)0x38, (byte)0x0D,
	    (byte)0x45, (byte)0x1D, (byte)0x0F, (byte)0x7C,
	    (byte)0x88, (byte)0xB3, (byte)0x1C, (byte)0x7C,
	    (byte)0x5B, (byte)0x2D, (byte)0x8E, (byte)0xF6,
	    (byte)0xF3, (byte)0xC9, (byte)0x23, (byte)0xC0,
	    (byte)0x43, (byte)0xF0, (byte)0xA5, (byte)0x5B,
	    (byte)0x18, (byte)0x8D, (byte)0x8E, (byte)0xBB,
	    (byte)0x55, (byte)0x8C, (byte)0xB8, (byte)0x5D,
	    (byte)0x38, (byte)0xD3, (byte)0x34, (byte)0xFD,
	    (byte)0x7C, (byte)0x17, (byte)0x57, (byte)0x43,
	    (byte)0xA3, (byte)0x1D, (byte)0x18, (byte)0x6C,
	    (byte)0xDE, (byte)0x33, (byte)0x21, (byte)0x2C,
	    (byte)0xB5, (byte)0x2A, (byte)0xFF, (byte)0x3C,
	    (byte)0xE1, (byte)0xB1, (byte)0x29, (byte)0x40,
	    (byte)0x18, (byte)0x11, (byte)0x8D, (byte)0x7C,
	    (byte)0x84, (byte)0xA7, (byte)0x0A, (byte)0x72,
	    (byte)0xD6, (byte)0x86, (byte)0xC4, (byte)0x03,
	    (byte)0x19, (byte)0xC8, (byte)0x07, (byte)0x29,
	    (byte)0x7A, (byte)0xCA, (byte)0x95, (byte)0x0C,
	    (byte)0xD9, (byte)0x96, (byte)0x9F, (byte)0xAB,
	    (byte)0xD0, (byte)0x0A, (byte)0x50, (byte)0x9B,
	    (byte)0x02, (byte)0x46, (byte)0xD3, (byte)0x08,
	    (byte)0x3D, (byte)0x66, (byte)0xA4, (byte)0x5D,
	    (byte)0x41, (byte)0x9F, (byte)0x9C, (byte)0x7C,
	    (byte)0xBD, (byte)0x89, (byte)0x4B, (byte)0x22,
	    (byte)0x19, (byte)0x26, (byte)0xBA, (byte)0xAB,
	    (byte)0xA2, (byte)0x5E, (byte)0xC3, (byte)0x55,
	    (byte)0xE9, (byte)0x2F, (byte)0x78, (byte)0xC7
	  };
	private static final BigInteger P_MODULUS = new BigInteger (1,SKIP_1024_MODULUS_BYTES);
	private static final BigInteger G_BASE = BigInteger.valueOf(2);
	private static final DHParameterSpec PARAMETER_SPEC = new DHParameterSpec(P_MODULUS,G_BASE);	//just a wrapper
	
	public static void main(String args[])
   	{  	
		int serverPort;	
		if (args.length != 1){
	    	System.out.println("Usage: java ChatServer port");
	    	return;
		}
		
		Runtime.getRuntime().addShutdownHook(new Thread() {
			public void run() {
				System.out.println("Cleanning up resources and shutting down server:");
				System.out.println("Closing connections ...");
				for(int i=0;i<cipherInPool.size();i++){
					try{
						if(cipherInPool.get(i)!=null)cipherInPool.get(i).close();
						if(cipherOutPool.get(i)!=null)cipherInPool.get(i).close();
						if(objectInPool.get(i)!=null)cipherInPool.get(i).close();
						if(objectOutPool.get(i)!=null)cipherInPool.get(i).close();
					}
					catch(IOException e){}
				}
				System.out.println("Serializing private table...");
				serializeTable();
				System.out.println("Encrypting private table...");
				encryptSerializedTable();
			}
		});
		
		serverPort = Integer.parseInt(args[0]);
		try {
			System.out.println("Starting server...");
			System.out.println("Decrypting private table...");
			decryptSerializedTable();
			System.out.println("Unserializing private table into memory...");
			unserializeTable();
			
			ServerSocket serverSocket = new ServerSocket(serverPort);
			System.out.println("Listening on port "+serverPort+"...");
			
			while(true) {
				Socket clientSocket = serverSocket.accept();//listen for new connections
				System.out.println("New client: "+clientSocket);
				ObjectOutputStream outputStream=new ObjectOutputStream(clientSocket.getOutputStream());
				outputStream.flush();
				ObjectInputStream inputStream=new ObjectInputStream(clientSocket.getInputStream());
				objectInPool.add(inputStream);
				objectOutPool.add(outputStream);
				Connection connection=new Connection(clientSocket,inputStream,outputStream);
				connection.start();
            }
			
		} catch (IOException e) {
			System.out.println("An error has ocurred: "+e.getMessage());
		}
   	}
	
	public static boolean serializeTable(){
		
		try{
			File f = new File(TABLE_FILE);
			f.createNewFile();
			
			OutputStream file = new FileOutputStream(TABLE_FILE);
			OutputStream buffer = new BufferedOutputStream(file);
			ObjectOutput output = new ObjectOutputStream(buffer);
			try{
				output.writeObject(table);
			}
			finally{
				output.close();
			}
		}
		catch(IOException e){
			System.out.println("An error has ocurred serializing data to disk: "+e.getMessage());
			e.printStackTrace();
			return false;
		}
		return true;
	}
	public static void unserializeTable(){
		
		try{
			File f = new File(TABLE_FILE);
			f.createNewFile();
			
			InputStream file = new FileInputStream(TABLE_FILE);
			InputStream buffer = new BufferedInputStream(file);
			ObjectInput input = new ObjectInputStream (buffer);
			try{
				table=(LookupTable)input.readObject();
			}
			finally{
				input.close();
			}
		}
		catch(Throwable e){
			table=new LookupTable();		//Unsuccessful, create a new table instead
			System.out.println("Could not unserialize the table. Created a new instead");
		}
	}
	public static boolean encryptSerializedTable(){
		
		//In a real world application, we could use a smartcard as the source of the pass, this is a just a proof of concept
		String smartcard="verysecurepassword";
		
		try {
			File f = new File(TABLE_FILE);
			File fe = new File(ENCRYPTED_TABLE_FILE);
			f.createNewFile();
			fe.createNewFile();
			
			FileInputStream fis = new FileInputStream(TABLE_FILE);
			FileOutputStream fos = new FileOutputStream(ENCRYPTED_TABLE_FILE);
			encrypt(smartcard, fis, fos);
			f.delete();

		} catch (Throwable e) {
			e.printStackTrace();
		}
		return true;
	}
	public static boolean decryptSerializedTable(){
		
		String smartcard="verysecurepassword";
		try {
			File f = new File(TABLE_FILE);
			File fe = new File(ENCRYPTED_TABLE_FILE);
			f.createNewFile();
			fe.createNewFile();
			
			FileInputStream fis = new FileInputStream(ENCRYPTED_TABLE_FILE);
			FileOutputStream fos = new FileOutputStream(TABLE_FILE);
			decrypt(smartcard, fis, fos);
		} catch (Throwable e) {
			e.printStackTrace();
		}
		return true;
	}
	public static void encrypt(String key, InputStream is, OutputStream os) throws Throwable {
		encryptOrDecrypt(key, Cipher.ENCRYPT_MODE, is, os);
	}

	public static void decrypt(String key, InputStream is, OutputStream os) throws Throwable {
		encryptOrDecrypt(key, Cipher.DECRYPT_MODE, is, os);
	}
	public static void encryptOrDecrypt(String key, int mode, InputStream is, OutputStream os) throws Throwable {

		DESKeySpec dks = new DESKeySpec(key.getBytes());
		SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
		SecretKey desKey = skf.generateSecret(dks);
		Cipher cipher = Cipher.getInstance("DES"); // DES/ECB/PKCS5Padding for SunJCE

		if (mode == Cipher.ENCRYPT_MODE) {
			cipher.init(Cipher.ENCRYPT_MODE, desKey);
			CipherInputStream cis = new CipherInputStream(is, cipher);
			doCopy(cis, os);
		} else if (mode == Cipher.DECRYPT_MODE) {
			cipher.init(Cipher.DECRYPT_MODE, desKey);
			CipherOutputStream cos = new CipherOutputStream(os, cipher);
			doCopy(is, cos);
		}
	}

	public static void doCopy(InputStream is, OutputStream os) throws IOException {
		byte[] bytes = new byte[64];
		int numBytes;
		while ((numBytes = is.read(bytes)) != -1) {
			os.write(bytes, 0, numBytes);
		}
		os.flush();
		os.close();
		is.close();
	}
	
	static class Connection extends Thread {
		
		public ObjectInputStream in;
		public ObjectOutputStream out;
		public ObjectInputStream cipherIn;
		public ObjectOutputStream cipherOut;
		public Socket clientSocket;
		public Record clientRecord=null;
		public String username;
		
		public Connection (Socket clientSocket,ObjectInputStream in,ObjectOutputStream out){
			this.in=in;
			this.out=out;
			this.clientSocket=clientSocket;
	    }
		
		public void run(){
			try{
				/*******HANDSHAKE PROTOCOL***********/
				Message syn=(Message)in.readObject();
				username=syn.getUsername();
				
				//check if its a new user or an existing one
				for(Record record:table.getTable()){
					if(record.getUsername().compareToIgnoreCase(username)==0){
						clientRecord=record;
					}
				}			
				
				if(clientRecord==null){	//new client
					try{
						syn.setMessage("NEW");
						out.writeObject(syn);
						out.reset();
						
						System.out.println("New client detected...\nInitiating the key agreement protocol with client: "+username);
						System.out.println("Generating a Diffie-Hellman KeyPair with client: "+username);
						KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
						kpg.initialize(PARAMETER_SPEC);
					    KeyPair keyPair = kpg.genKeyPair();
					    
					    System.out.println("Sending the server public key to client: "+username);
					    byte[] keyBytes = keyPair.getPublic().getEncoded();
					    syn.setEncondedPublicKey(keyBytes);
					    out.writeObject(syn);
					    out.reset();
					    
					    System.out.println("Receiving client's public key: "+username);
					    syn=(Message)in.readObject();
					    keyBytes = syn.getEncondedPublicKey();
					    KeyFactory kf = KeyFactory.getInstance("DH");
					    X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(keyBytes);
					    PublicKey clientPublicKey = kf.generatePublic(x509Spec);
					    
					    System.out.println("Performing the KeyAgreement with client: "+username);
					    KeyAgreement ka = KeyAgreement.getInstance("DH");
					    ka.init(keyPair.getPrivate());
					    ka.doPhase(clientPublicKey,true);
					    
					    System.out.println("Create and send the IVParameterSpec to the client: "+username);
					    byte[] initializationVector = new byte[8];
					    SecureRandom random = new SecureRandom();
					    random.nextBytes(initializationVector);
					    syn.setInitializationVector(initializationVector);
					    out.writeObject(syn);
					    out.reset();
					    
					    System.out.println("Creating a session key with client: "+username);
					    byte[] sessionKeyBytes = ka.generateSecret();
					    SecretKeyFactory skf = SecretKeyFactory.getInstance("TripleDES");
					    DESedeKeySpec tripleDesSpec = new DESedeKeySpec(sessionKeyBytes);
					    SecretKey sessionKey = skf.generateSecret(tripleDesSpec);
					    
					    System.out.println("Creating the CipherStreams to be used with client: "+username);
					    
					    Cipher decrypter = Cipher.getInstance("TripleDES/CFB8/NoPadding");
					    Cipher encrypter = Cipher.getInstance("TripleDES/CFB8/NoPadding");
					    
					    IvParameterSpec spec = new IvParameterSpec(initializationVector);
					    
					    encrypter.init(Cipher.ENCRYPT_MODE, sessionKey, spec);
					    decrypter.init(Cipher.DECRYPT_MODE, sessionKey, spec);
					    
					    cipherOut = new ObjectOutputStream(new CipherOutputStream(out, encrypter));
					    cipherOut.flush();
					    cipherIn = new ObjectInputStream(new CipherInputStream(in, decrypter));
					    
					    //add these channels to the list of known connections, must be synchronized
					    synchronized(this) {
					    	cipherInPool.add(cipherIn);
						    cipherOutPool.add(cipherOut);
						    objectInPool.add(in);
						    objectOutPool.add(out);
						    onlineUsers.add(username);
					    }
					    
					    //add a new table entry for future connections
					    SessionKey key=new SessionKey(initializationVector,sessionKey);
					    Record record=new Record(username,key,System.currentTimeMillis());
					    table.addRecord(record);
					    
					    //send a success message
					    syn.setMessage("Successfully Established a Secure Connection with server");
					    cipherOut.writeObject(syn);
					    cipherOut.reset();
					    cipherOut.flush();
					    
					    System.out.println("Successfully Established a Secure Connection with client: "+username);
					}
				    catch (GeneralSecurityException ex){
				       System.out.println("An error has ocurred ...\nDetails: "+ex.getMessage());
				       ex.printStackTrace();
				    }
				}
				else{//existing client
					try{
						syn.setMessage("KNOWN");
						out.writeObject(syn);
						out.reset();
						out.flush();
						
						System.out.println("Known client detected... "+username);
						
//						syn=(Message)in.readObject();
//						if(syn.getMessage().compareToIgnoreCase("FAIL")==0){	//log and close invalid connection
//							System.out.println("WARNING: client "+username+" attempted to login but failed!");
//							clientSocket.close();
						
						//a ver se isto dá bode
						
//							return;
//						}
						
						
						System.out.println("Creating the CipherStreams to be used with client: "+username);
						
						byte[] initializationVector=clientRecord.getSessionKey().getSpecification();
						SecretKey sessionKey=clientRecord.getSessionKey().getSessionkey();
						
						Cipher decrypter = Cipher.getInstance("TripleDES/CFB8/NoPadding");
					    Cipher encrypter = Cipher.getInstance("TripleDES/CFB8/NoPadding");
					    
					    IvParameterSpec spec = new IvParameterSpec(initializationVector);
					    
					    encrypter.init(Cipher.ENCRYPT_MODE, sessionKey, spec);
					    decrypter.init(Cipher.DECRYPT_MODE, sessionKey, spec);
					    
					    cipherOut = new ObjectOutputStream(new CipherOutputStream(out, encrypter));
					    cipherOut.flush();
					    cipherIn = new ObjectInputStream(new CipherInputStream(in, decrypter));
					    
					    //add these channels to the list of known connections, must be synchronized
					    synchronized(this) {
					    	cipherInPool.add(cipherIn);
						    cipherOutPool.add(cipherOut);
						    objectInPool.add(in);
						    objectOutPool.add(out);
						    onlineUsers.add(username);
					    }
					    
					    //send a success message
					    syn.setMessage("Successfully Established a Secure Connection with server");
					    cipherOut.writeObject(syn);
					    cipherOut.reset();
					    cipherOut.flush();
					    
					    System.out.println("Successfully Established a Secure Connection with client: "+username);
						
					}
					catch(GeneralSecurityException ex){
						System.out.println("An error has ocurred ...\nDetails: "+ex.getMessage());
					    if(DEBUG)ex.printStackTrace();
					}
				}
				
				
				//listen for incoming messages and echoes them
				Message message;
				while(true){
					message=(Message)cipherIn.readObject();
					for(int i=0;i<cipherOutPool.size();i++){
						ObjectOutputStream encryptedChannel=cipherOutPool.get(i);
						if(DEBUG)System.out.println("Forwarding message to "+onlineUsers.get(i));
						try{
							if(onlineUsers.get(i).compareToIgnoreCase(message.getUsername())!=0){	//avoid ping-pong
								encryptedChannel.writeObject(message);
								encryptedChannel.reset();
								encryptedChannel.flush();
							}
						}
						catch(IOException e){ //remove offline user
							if(username==null) username="?";
							System.out.println("Client "+username+" was disconnected. Details: "+ e.getMessage());
							if(DEBUG)e.printStackTrace();
							synchronized(this) {
								cipherInPool.remove(i);
							    cipherOutPool.remove(i);
							    objectInPool.remove(i);
							    objectOutPool.remove(i);
							    onlineUsers.remove(i);
							}
							i--;
						}
					}
				}
			}
			catch(IOException e){ //remove offline user
				
			}
			catch (ClassNotFoundException e) {
			}
		}
		
		

	}
}