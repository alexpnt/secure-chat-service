import java.io.Serializable;

/*
 * Representation of the message
 */
public class Message implements Serializable{
	private static final long serialVersionUID = 1L;
	
	private String username;
	private String message;
	
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

}
