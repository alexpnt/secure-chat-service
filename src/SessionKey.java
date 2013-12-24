import java.io.Serializable;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/*
 * Class used to store a shared session key and a specification vector used to create a cypher stream
 */
public class SessionKey implements Serializable{
	
	private static final long serialVersionUID = 1L;
	private IvParameterSpec specification;		//specifies an initialization vector, used to initialize a cypher while encrypting data .
	private SecretKey sessionkey;					//a shared session key
	
	public SessionKey(IvParameterSpec specification, SecretKey sessionkey) {
		super();
		this.specification = specification;
		this.sessionkey = sessionkey;
	}
	public IvParameterSpec getSpecification() {
		return specification;
	}
	public void setSpecification(IvParameterSpec specification) {
		this.specification = specification;
	}
	public SecretKey getSessionkey() {
		return sessionkey;
	}
	public void setSessionkey(SecretKey sessionkey) {
		this.sessionkey = sessionkey;
	}
}
