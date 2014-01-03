import java.io.Serializable;

/*
 * A record of a lookup table
 */
public class Record implements Serializable{
	private static final long serialVersionUID = 1L;
	
	private String username;			//An identificator, must be unique
	private SessionKey sessionKey;	//The session key used in communications with this client
	private long timeStamp;			//A timestamp used to store the last time the session key of this record was updated (useful for periodic key updates)
	
	
	public Record(String username, SessionKey sessionKey, long timeStamp) {
		super();
		this.username = username;
		this.sessionKey = sessionKey;
		this.timeStamp = timeStamp;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public SessionKey getSessionKey() {
		return sessionKey;
	}
	public void setSessionKey(SessionKey sessionKey) {
		this.sessionKey = sessionKey;
	}
	public long getTimeStamp() {
		return timeStamp;
	}
	public void setTimeStamp(long timeStamp) {
		this.timeStamp = timeStamp;
	}
	
	
	
	
	
		
}