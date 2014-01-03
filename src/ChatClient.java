import java.io.*;
import java.net.*;
import java.math.*;
import java.security.*;
import java.security.spec.*;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.*;

public class ChatClient{
	private static ObjectInputStream cipherIn;					//secure channels
	private static ObjectOutputStream cipherOut;
	private static ObjectInputStream in;;						//insecure channels
	private static ObjectOutputStream out;

	
	private static Boolean DEBUG=false;
	
	private static String KEY_DIR = "data/"; // location of the secret key
	public boolean readFromThread=true;
    PipedInputStream pin = null;
    PipedOutputStream pout = null;
	
	public ChatClient() {
		
	}
	
	public static void main(String args[]){
		ChatClient chatClient=new ChatClient();
		chatClient.Init();
	}
	
	public void Init(){

        try {
            pin = new PipedInputStream();
            pout = new PipedOutputStream(pin);
        }
        catch (IOException e) {
            System.out.println("Pipe connect fail...");
        }
		
		
		Scanner scan = new Scanner(System.in);
		String username;
		System.out.println("\nUsername:");
		username=scan.nextLine();
		//Starts the thread responsible for the connection
		Input inputBuffer=new Input(username,this);
		inputBuffer.start();
		
		String msg = "";
	    InputStreamReader inputStream = new InputStreamReader(System.in);
	    BufferedReader reader = new BufferedReader(inputStream);
	    Message m;
		

	    
		while(true){
		    try {
		    	System.out.println("Write a message: ");
			    msg=reader.readLine();
			    if(readFromThread){
			    	pout.write(msg.getBytes());
			    	readFromThread=false;
				    synchronized (this) {
						try {
							this.wait();
						} catch (InterruptedException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
				    
				    if(DEBUG)System.out.println("Notify received");
			    }else{
				    m=new Message(username,msg);
				    m.assureIntegrity();
				    cipherOut.writeObject(m);
				    cipherOut.reset();
				    cipherOut.flush();
				    System.out.println();
			    }
			} catch (IOException e) {
				System.out.println("Server is Down");
				if(DEBUG) e.printStackTrace();
				//waits for the Input thread to connect
				synchronized (this) {
					try {
						this.wait();
					} catch (InterruptedException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
			    if(DEBUG)System.out.println("Notify received");
			}
		}
				
	}
	

	public boolean serializeSessionKey(String keyFilename, SessionKey sessionKey) {

		try {
			File f = new File(keyFilename);
			System.out.println(keyFilename);
			System.out.println(f.getAbsolutePath());
			f.createNewFile();

			OutputStream file = new FileOutputStream(keyFilename);
			OutputStream buffer = new BufferedOutputStream(file);
			ObjectOutput output = new ObjectOutputStream(buffer);
			try {
				output.writeObject(sessionKey);
			} finally {
				output.close();
			}
		} catch (IOException e) {
			System.out.println("An error has ocurred serializing key to disk: "	+ e.getMessage());
			if (DEBUG)
				e.printStackTrace();
			return false;
		}
		return true;
	}

	public SessionKey unserializeSessionKey(String keyFilename) {

		SessionKey sessionKey = null;

		try {
			File f = new File(keyFilename);
			System.out.println(keyFilename);
			f.createNewFile();

			InputStream file = new FileInputStream(keyFilename);
			InputStream buffer = new BufferedInputStream(file);
			ObjectInput input = new ObjectInputStream(buffer);
			try {
				sessionKey = (SessionKey) input.readObject();
			} finally {
				input.close();
				f.delete();
			}
		} catch (Throwable e) {
			if (DEBUG) {
				System.out
						.println("An error has ocurred unserializing key to memory: "
								+ e.getMessage());
				e.printStackTrace();
			}
		}
		return sessionKey;
	}

	public boolean encryptSerializedKey(String password, String keyFilename,
			String keyFilenameEncrypted) {

		try {
			File f = new File(keyFilename);
			File fe = new File(keyFilenameEncrypted);
			System.out.println(keyFilename);
			f.createNewFile();
			fe.createNewFile();

			FileInputStream fis = new FileInputStream(keyFilename);
			FileOutputStream fos = new FileOutputStream(keyFilenameEncrypted);
			encrypt(password, fis, fos);
			f.delete();

		} catch (Throwable e) {
			if (DEBUG)
				e.printStackTrace();
		}
		return true;
	}

	public boolean decryptSerializedKey(String password, String keyFilename,
			String keyFilenameEncrypted) {

		try {
			File f = new File(keyFilename);
			File fe = new File(keyFilenameEncrypted);

			System.out.println(f.getAbsolutePath());
			f.createNewFile();
			fe.createNewFile();

			FileInputStream fis = new FileInputStream(keyFilenameEncrypted);
			FileOutputStream fos = new FileOutputStream(keyFilename);
			decrypt(password, fis, fos);
		} catch (Throwable e) {
			if (DEBUG)
				e.printStackTrace();
		}
		return true;
	}

	public void encrypt(String key, InputStream is, OutputStream os)
			throws Throwable {
		encryptOrDecrypt(key, Cipher.ENCRYPT_MODE, is, os);
	}

	public void decrypt(String key, InputStream is, OutputStream os)
			throws Throwable {
		encryptOrDecrypt(key, Cipher.DECRYPT_MODE, is, os);
	}

	public void encryptOrDecrypt(String key, int mode, InputStream is,OutputStream os) throws Throwable {

		DESKeySpec dks = new DESKeySpec(key.getBytes());
		SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
		SecretKey desKey = skf.generateSecret(dks);
		Cipher cipher = Cipher.getInstance("DES"); // DES/ECB/PKCS5Padding for
													// SunJCE

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

	
	class Input extends Thread {
		Message message;
		String username;
		ChatClient chatClient;
		Input(String username, ChatClient chatClient){
			message=new Message("","");
			this.username=username;
			this.chatClient=chatClient;
		}
		
		public void run(){
			while(true){
				Socket socket = null;
				int serverPort=8000;	
				String host="127.0.0.1";

		//		if (args.length != 2){
		//            System.out.println("Usage: java ChatClient host port");
		//            return;
		//		}
		//		host=args[0];
		//		serverPort = Integer.parseInt(args[1]);
				System.out.println("Trying to connect to "+host+", port "+serverPort+".");
				
				try{
					socket = new Socket(host,serverPort);
					
					out = new ObjectOutputStream(socket.getOutputStream());
					out.flush();
					in = new ObjectInputStream(socket.getInputStream());
					
					System.out.println("Insecure Connection Established.");
					
					//receive the username from the user
		
					String message;
					/*******HANDSHAKE PROTOCOL***********/
					Message syn=new Message(username,"");		//send the username
					out.writeObject(syn);
					out.reset();
					
					syn=(Message)in.readObject();				//receive the server reply
					message=syn.getMessage();					

					Scanner scan=new Scanner(System.in);
					if(message.compareToIgnoreCase("NEW")==0){			
						DiffieHellman df=new DiffieHellman();
						df.createNewKey(username, true, in, out);
						cipherIn=df.getCipherIn();
						cipherOut=df.getCipherOut();
						
						// save the session key in an encrypted file for future
						// reference
						System.out.println("Saving and encrypting your session key ...");
						String keyFilename = KEY_DIR + username + "_key";
						String keyFilenameEncrypted = KEY_DIR + username + "_key_DES";
		
						serializeSessionKey(keyFilename, new SessionKey(df.getInitializationVector(), df.getSessionKey()));
		
						System.out.println("We have detected you are a new client or your password has expired.\n"
										+ "A password is required in order to encrypt your session key.\n"
										+ "Remember, only you will know about this password. We will not store it anywhere.\n"
										+ "This is your master and private key.\n"
										+ "Please enter a passphrase:");
		
						String pass1 = null, pass2 = null;
						char[] passwd;
						Console cons;
						
						chatClient.readFromThread=true;
						byte[]temp=new byte[100];
						pin.read(temp);
						pass1=temp.toString();
		//				do{
		//				System.out.println("\n[Both passwords must match and be at least 8 characters]");
		//				if ((cons = System.console()) != null && (passwd = cons.readPassword("[%s]", "Password:")) != null) {
		//					pass1=new String(passwd);
		//				    java.util.Arrays.fill(passwd,' ');
		//				}
		//				
		//				System.out.print("Please retype it:\n");
		//				if ((cons = System.console()) != null && (passwd = cons.readPassword("[%s]", "Password:")) != null) {
		//					pass2=new String(passwd);
		//				    java.util.Arrays.fill(passwd,' ');
		//				}
		//				
		//			}while(pass1.compareTo(pass2)!=0 || pass1.length()<8);
		
						encryptSerializedKey(pass1, keyFilename, keyFilenameEncrypted);
		
						syn = (Message) cipherIn.readObject();
						System.out.println(syn.getMessage());
					}
					else{
						System.out.println("We have detected you are a returning client.\n"
								+ "Please enter your passphrase in order to initiate session:");
								
						String pass1=null,pass2=null;
						char[] passwd;
						Console cons;
						
						chatClient.readFromThread=true;
						byte[]temp=new byte[100];
						pin.read(temp);
						pass1=temp.toString();
		//				do{
		//					System.out.println("\n[Both passwords must match and be at least 8 characters]");
		//					if ((cons = System.console()) != null && (passwd = cons.readPassword("[%s]", "Password:")) != null) {
		//						pass1=new String(passwd);
		//					    java.util.Arrays.fill(passwd,' ');
		//					}
		//					
		//					System.out.print("Please retype it:\n");
		//					if ((cons = System.console()) != null && (passwd = cons.readPassword("[%s]", "Password:")) != null) {
		//						pass2=new String(passwd);
		//					    java.util.Arrays.fill(passwd,' ');
		//					}
		//					
		//				}while(pass1.compareTo(pass2)!=0 || pass1.length()<8);
						
						System.out.println("Retrieving your session key ...");
						String keyFilename =KEY_DIR+username+"_key";
					    String keyFilenameEncrypted =KEY_DIR+username+"_key_DES";
						decryptSerializedKey(pass1, keyFilename, keyFilenameEncrypted);
						SessionKey sessionKey=unserializeSessionKey(keyFilename);
						if(sessionKey==null){
							System.out.println("An error has ocurred while retrieving your session key. Possible causes:\n"
									+ "\t->You entered a wrong password :/.\n"
									+ "\t->You are an intruder >:).");
							File f = new File(keyFilename);
							f.delete();
		
							return;
						}
		
						System.out.println("Success!\nCreating the CipherStreams to be used with server...");
						
						try{
							
							Cipher decrypter = Cipher.getInstance("TripleDES/CFB8/NoPadding");
						    Cipher encrypter = Cipher.getInstance("TripleDES/CFB8/NoPadding");
						    
						    IvParameterSpec spec = new IvParameterSpec(sessionKey.getSpecification());
						    
						    encrypter.init(Cipher.ENCRYPT_MODE, sessionKey.getSessionkey(), spec);
						    decrypter.init(Cipher.DECRYPT_MODE, sessionKey.getSessionkey(), spec);
						    
						    cipherOut = new ObjectOutputStream(new CipherOutputStream(out, encrypter));
						    cipherOut.flush();
						    cipherIn = new ObjectInputStream(new CipherInputStream(in, decrypter));
						    
						    syn=(Message)cipherIn.readObject();
						    System.out.println(syn.getMessage());
						}
						 catch (GeneralSecurityException ex){
					       System.out.println("An error has ocurred ...\nDetails: "+ex.getMessage());
					       ex.printStackTrace();
						 }
					}
					synchronized (chatClient) {
						chatClient.notify();	
					}
					
					while(true){
						syn=(Message)cipherIn.readObject();
						if(syn.verifyIntegrity()){
							if(syn.getMessage().compareTo("TIMEOUT")==0){
								System.out.println("key expired");
								cipherOut.close();
								break;
							}
							else{
								System.out.println("\nNew message from "+syn.getUsername()+": "+syn.getMessage()+"\n");
							}
						}
						else{
							System.out.println("\nThe message was modified by a third party. Lets create a new session key");
							cipherOut.close();
							break;
						}
					}
				}catch (IOException e) {
					System.out.println("An error has ocurred. Attempting to reconnect ");
					if(DEBUG) e.printStackTrace();
					try {
						Thread.sleep(5000);
					} catch (InterruptedException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				} catch (ClassNotFoundException e) {
					if(DEBUG)e.printStackTrace();
				}
			}
		}
	}
	
}