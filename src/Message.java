import java.io.Serializable;

/*
 * Representation of the message
 */
public class Message implements Serializable{
	private static final long serialVersionUID = 1L;
	
	private String username;
	private String message;
	private byte[] encondedPublicKey;
	private byte[] initializationVector;
	
	
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

}
