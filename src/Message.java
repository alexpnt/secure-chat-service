import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/*
 * Representation of the message
 */
public class Message implements Serializable{
	private static final long serialVersionUID = 1L;
	
	private String username;
	private String message;
	private byte[] encondedPublicKey;
	private byte[] initializationVector;
	private byte[] messageDigest;
	private long timeStamp;	
	
	
	public Message(String username, String message) {
		super();
		this.username = username;
		this.message = message;
	}
	
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getMessage() {
		return message;
	}
	public void setMessage(String message) {
		this.message = message;
	}
	public byte[] getEncondedPublicKey() {
		return encondedPublicKey;
	}

	public void setEncondedPublicKey(byte[] encondedPublicKey) {
		this.encondedPublicKey = encondedPublicKey;
	}
	public byte[] getInitializationVector() {
		return initializationVector;
	}

	public void setInitializationVector(byte[] initializationVector) {
		this.initializationVector = initializationVector;
	}

	public long getTimeStamp() {
		return timeStamp;
	}

	public void setTimeStamp(long timeStamp) {
		this.timeStamp = timeStamp;
	}
	
	public boolean verifyIntegrity(){
        MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("MD5");
			if(	Arrays.equals( digest.digest((username+message).getBytes("UTF-8")), messageDigest) ){
				return true;
			}
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	public void assureIntegrity(){
        MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("MD5");
			messageDigest=digest.digest((username+message).getBytes("UTF-8"));

		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

}
