import java.io.Serializable;

import javax.crypto.SecretKey;

/*
 * Class used to store a shared session key and a specification vector used to create a cypher stream
 */
public class SessionKey implements Serializable{
	
	private static final long serialVersionUID = 1L;
	private  byte[] initializationVector;		//specifies an initialization vector, used to initialize a cypher while encrypting data .
	private SecretKey sessionkey;				//a shared session key
	
	public SessionKey(){}
	
	public SessionKey( byte[] specification, SecretKey sessionkey) {
		super();
		this.initializationVector = specification;
		this.sessionkey = sessionkey;
	}
	public  byte[] getSpecification() {
		return initializationVector;
	}
	public void setSpecification(byte[] specification) {
		this.initializationVector = specification;
	}
	public SecretKey getSessionkey() {
		return sessionkey;
	}
	public void setSessionkey(SecretKey sessionkey) {
		this.sessionkey = sessionkey;
	}
}
