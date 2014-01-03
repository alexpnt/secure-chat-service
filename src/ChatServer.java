import java.io.*;
import java.net.*;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ChatServer{
	ChatServer server;
	
	private final String TABLE_FILE = "../data/LookupTable.ser";
	private final String ENCRYPTED_TABLE_FILE = "../data/LookupTable_DES";
	
	private List <Connection> connections = new ArrayList<Connection>();
	
	private Boolean DEBUG=false;
	
	private LookupTable table;
	
	public ChatServer() {}
	
	public void init(ChatServer server,String args[]){
		this.server=server;
		ExpirationChecker expirationChecker=new ExpirationChecker(server);
		expirationChecker.start();
		int serverPort;	
	    
		try{
			serverPort = Integer.parseInt(args[0]);
		}catch(Exception e){
			serverPort=8000;
		}
		
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
		chatServer.init(chatServer,args);
		
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
				if(username==null) username="?";
				System.out.println("Client "+username+" was disconnected.");
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
//							e.printStackTrace();
//						}
//						break;
					}
				}
				
			}
		}
	}
}