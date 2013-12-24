import java.io.*;
import java.net.*;
import java.math.*;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class ChatClient{
	public static CipherInputStream cipherIn;
	public static CipherOutputStream cipherOut;
	public static ObjectInputStream in;;
	public static ObjectOutputStream out;
	
	public static void main(String args[]){
		
		Socket socket = null;
		int serverPort;	
		String host;
		
		if (args.length != 2){
            System.out.println("Usage: java ChatClient host port");
            return;
		}
		host=args[0];
		serverPort = Integer.parseInt(args[1]);
		System.out.println("Trying to connect to "+host+", port "+serverPort+".");
		
		try{
			socket = new Socket(host,serverPort);
			
			out = new ObjectOutputStream(socket.getOutputStream());
			out.flush();
			in = new ObjectInputStream(socket.getInputStream());
			
			System.out.println("Insecure Connection Established.");
			
			//receive the username from the user
			Scanner scan = new Scanner(System.in);
			String username,message;
			System.out.println("\nUsername:");
			username=scan.next();
			username+=scan.nextLine();
			
			/*******HANDSHAKE PROTOCOL***********/
			Message syn=new Message(username,"");
			out.writeObject(syn);
			
			syn=(Message)in.readObject();
			System.out.println("Message from the server: "+syn.getMessage());
			
			
		}
		catch (IOException e) {
			System.out.println("An error has ocurred: "+e.getMessage());
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		
		
	}
}