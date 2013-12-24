import java.io.*;
import java.net.*;
import java.math.*;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class ChatServer{
	
	private static final String TABLE_FILE = "../data/LookupTable.ser";
	private static final String ENCRYPTED_TABLE_FILE = "../data/encryptedTable";
	
	public static List<CipherInputStream> cipherInPool = new ArrayList<CipherInputStream>();				//Secure channels
	public static List<CipherOutputStream> cipherOutPool = new ArrayList<CipherOutputStream>();
			
	public static List <ObjectInputStream> objectInPool = new ArrayList<ObjectInputStream>();				//Insecure channels
	public static List <ObjectOutputStream> objectOutPool = new ArrayList<ObjectOutputStream>();
	
	public static LookupTable table;
	
	public static void main(String args[])
   	{  	
		int serverPort;	
		if (args.length != 1){
	    	System.out.println("Usage: java ChatServer port");
	    	return;
		}
		
		Runtime.getRuntime().addShutdownHook(new Thread() {
			public void run() {
				System.out.println("Cleanning up resources and shutting down server.");
				for(int i=0;i<cipherInPool.size();i++){
					try{
						cipherInPool.get(i).close();
						cipherOutPool.get(i).close();
						objectInPool.get(i).close();
						objectOutPool.get(i).close();
					}
					catch(IOException e){}
					serializeTable();
					encryptSerializedTable();
				}
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
				Connection connection=new Connection(inputStream,outputStream);
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
				LookupTable table=(LookupTable)input.readObject();
			}
			finally{
				input.close();
			}
		}
		catch(Throwable e){
			table=new LookupTable();		//Unsuccessful, create a new table instead
		}
	}
	public static boolean encryptSerializedTable(){
		
		String smartcard="verysecurepassword";		//In a real world application, we could use a smartcard as the source of the pass, this is a just a proof of concept
		
		try {
			File f = new File(TABLE_FILE);
			File fe = new File(ENCRYPTED_TABLE_FILE);
			f.createNewFile();
			fe.createNewFile();
			
			FileInputStream fis = new FileInputStream(TABLE_FILE);
			FileOutputStream fos = new FileOutputStream(ENCRYPTED_TABLE_FILE);
			encrypt(smartcard, fis, fos);

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
		
		public Connection (ObjectInputStream in,ObjectOutputStream out){
			this.in=in;
			this.out=out;
	    }
		
		public void run(){
			try{
				/*******HANDSHAKE PROTOCOL***********/
				Message syn=(Message)in.readObject();
				String username=syn.getUsername();
				
				syn.setMessage("Hello "+username);
				out.writeObject(syn);
			}
			catch(IOException e){
			}
			catch (ClassNotFoundException e) {
			}
		}
		
		

	}
}