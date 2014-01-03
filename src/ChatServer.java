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
	
	
	ChatServer server;
	
	
	private final String TABLE_FILE = "data/LookupTable.ser";
	private final String ENCRYPTED_TABLE_FILE = "data/LookupTable_DES";
	
	private List <Connection> connections = new ArrayList<Connection>();
	
	private Boolean DEBUG=false;
	
	private LookupTable table;
	
	/*
	 * 
	 * Diffie-Hellman Parameters for 1024 bits Modulus (1024-bit prime modulus P, base G)
	 * 
	 */
	private final byte SKIP_1024_MODULUS_BYTES[] = {
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
	private final BigInteger P_MODULUS = new BigInteger (1,SKIP_1024_MODULUS_BYTES);
	private final BigInteger G_BASE = BigInteger.valueOf(2);
	private final DHParameterSpec PARAMETER_SPEC = new DHParameterSpec(P_MODULUS,G_BASE);	//just a wrapper
	
	
	public ChatServer() {
		
	}
	
	public void init(ChatServer server){
		this.server=server;
		ExpirationChecker expirationChecker=new ExpirationChecker(server);
		int serverPort=8000;	
//		if (args.length != 1){
//	    	System.out.println("Usage: java ChatServer port");
//	    	return;
//		}
//		serverPort = Integer.parseInt(args[0]);
		
		Runtime.getRuntime().addShutdownHook(new Thread() {
			public void run() {
				System.out.println("Cleanning up resources and shutting down server:");
				System.out.println("Closing connections ...");
				for(Connection con:connections){
					try{
						if(con.in!=null) con.in.close();
						if(con.out!=null)con.out.close();
						if(con.cipherIn!=null)con.cipherIn.close();
						if(con.cipherOut!=null)con.cipherOut.close();
					}
					catch(IOException e){}
				}
				System.out.println("Serializing private table...");
				serializeTable();
				System.out.println("Encrypting private table...");
				encryptSerializedTable();
			}
		});
		
		
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

				Connection connection=new Connection(this,clientSocket,inputStream,outputStream);
				synchronized(this){
					connections.add(connection);
				}
				connection.start();
            }
			
		} catch (IOException e) {
			System.out.println("An error has ocurred: "+e.getMessage());
		}
		
		
	}
	
	public static void main(String args[])
   	{  	
		ChatServer chatServer=new ChatServer();
		chatServer.init(chatServer);
		
   	}
	
	public boolean serializeTable(){
		
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
	public void unserializeTable(){
		
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
	public boolean encryptSerializedTable(){
		
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
	public boolean decryptSerializedTable(){
		
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
	public void encrypt(String key, InputStream is, OutputStream os) throws Throwable {
		encryptOrDecrypt(key, Cipher.ENCRYPT_MODE, is, os);
	}

	public void decrypt(String key, InputStream is, OutputStream os) throws Throwable {
		encryptOrDecrypt(key, Cipher.DECRYPT_MODE, is, os);
	}
	public void encryptOrDecrypt(String key, int mode, InputStream is, OutputStream os) throws Throwable {

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

	public void doCopy(InputStream is, OutputStream os) throws IOException {
		byte[] bytes = new byte[64];
		int numBytes;
		while ((numBytes = is.read(bytes)) != -1) {
			os.write(bytes, 0, numBytes);
		}
		os.flush();
		os.close();
		is.close();
	}
	
	class Connection extends Thread {
		ChatServer server;
		
		public ObjectInputStream in;
		public ObjectOutputStream out;
		public ObjectInputStream cipherIn;
		public ObjectOutputStream cipherOut;
		public Socket clientSocket;
		public Record clientRecord=null;
		public String username;
		
		public Connection (ChatServer server, Socket clientSocket,ObjectInputStream in,ObjectOutputStream out){
			this.in=in;
			this.out=out;
			this.clientSocket=clientSocket;
			this.server=server;
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
						break;
					}
				}			
				
				if(clientRecord==null || (clientRecord!=null && (System.currentTimeMillis()- clientRecord.getTimeStamp() > 80000) )){	//new client
					System.out.println("Initiating the key agreement protocol with client: "+username);
					syn.setMessage("NEW");
					out.writeObject(syn);
					out.reset();
					
					DiffieHellman df=new DiffieHellman();
					df.createNewKey(username, false, in, out);
					cipherIn=df.getCipherIn();
					cipherOut=df.getCipherOut();
					synchronized (server) {
						if(clientRecord==null)
							server.table.addRecord(df.getRecord());
						else
							server.table.updateRecord(df.getRecord());
					}		    
					//send a success message
					syn.setMessage("Successfully Established a Secure Connection with server");
					cipherOut.writeObject(syn);
					cipherOut.reset();
					cipherOut.flush();
					
					System.out.println("Successfully Established a Secure Connection with client: "+username);
				}
				else{//existing client
					try{
						syn.setMessage("KNOWN");
						out.writeObject(syn);
						out.reset();
						out.flush();
						
						System.out.println("Known client detected... "+username);
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
					System.out.println("Received message from "+  message.getUsername());
					if(message.verifyIntegrity()){
						for(int i=0;i<connections.size();i++){
							Connection conn=connections.get(i);
							ObjectOutputStream encryptedChannel=conn.cipherOut;
							if(DEBUG)System.out.println("Forwarding message to "+conn.username);
							try{
								if(conn.username.compareToIgnoreCase(message.getUsername())!=0){	//avoid ping-pong
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
									connections.remove(i);
								}
								i--;
							}
						}
					}
					else{
						//BORA FAZER UMA NOVA CHAVE
						System.out.println("Establish new key with client");
						break;
					}
				}
			}
			catch(IOException e){ //remove offline user
				System.out.println("Connections was closed");
				if(DEBUG) e.printStackTrace();
				synchronized(this) {
					connections.remove(this);
				}
			}
			catch (ClassNotFoundException e) {
			}
		}
		
	}
	
	class ExpirationChecker extends Thread{
		private ChatServer server;
		
		ExpirationChecker(ChatServer server) {
			this.server=server;
			this.start();
		}
		
		public void run(){
			while(true){
				try {
					Thread.sleep(60000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				checkExpiration();
				saveData();
			}
		}
		
		void saveData(){
			System.out.println("Serializing private table...");
			serializeTable();
			System.out.println("Encrypting private table...");
			encryptSerializedTable();
		}
		
		void checkExpiration(){
			for(Record rec:server.table.getTable() ){		
				for(Connection conn:server.connections){
					if(conn.username.compareTo(rec.getUsername())==0 && (System.currentTimeMillis()- rec.getTimeStamp() > 80000)){
						Message mes=new Message("server","TIMEOUT");
						mes.assureIntegrity();
						try {
							conn.cipherOut.writeObject(mes);
							conn.cipherOut.reset();
							conn.cipherOut.flush();
						} catch (IOException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
						break;
						
						
						
//						try {
//							conn.cipherOut.writeObject(mes);
//							conn.cipherOut.reset();
//							conn.cipherOut.flush();
//							
//							System.out.println("Client "+conn.username+" key has expired. Creating new key for him");
//
//							DiffieHellman df=new DiffieHellman();
//							df.createNewKey(conn.username, false, conn.in, conn.out);
//							conn.cipherIn=df.getCipherIn();
//							conn.cipherOut=df.getCipherOut();
//							synchronized (server) {
//								server.table.updateRecord(df.getRecord());
//							}		    
//							//send a success message
//							mes.setMessage("Successfully Established a Secure Connection with server");
//							conn.cipherOut.writeObject(mes);
//							conn.cipherOut.reset();
//							conn.cipherOut.flush();
//							
//							System.out.println("Successfully Established a Secure Connection with client: "+conn.username);
//							
//						} catch (IOException e) {
//							// TODO Auto-generated catch block
//							e.printStackTrace();
//						}
//						break;
					}
				}
				
			}
		}
	}
}