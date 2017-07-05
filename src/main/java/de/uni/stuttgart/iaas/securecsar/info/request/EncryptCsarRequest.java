package de.uni.stuttgart.iaas.securecsar.info.request;

import de.uni.stuttgart.iaas.securecsar.info.KeystoreInfo;

public class EncryptCsarRequest {
	private String encryptedBy;
	private String encryptorContact;
	private byte[] csar;
	private String csarName;
	private KeystoreInfo keystoreInfo;
	private String encAlg;
	
	public EncryptCsarRequest () {
		
	}
	
	public byte[] getCsar() {
		return csar;
	}
	public void setCsar(byte[] csar) {
		this.csar = csar;
	}
	public String getCsarName() {
		return csarName;
	}
	public void setCsarName(String csarName) {
		this.csarName = csarName;
	}
	public KeystoreInfo getKeystoreInfo() {
		return keystoreInfo;
	}
	public void setKeystoreInfo(KeystoreInfo keystoreInfo) {
		this.keystoreInfo = keystoreInfo;
	}
	public String getEncAlg() {
		return encAlg;
	}
	public void setEncAlg(String encAlg) {
		this.encAlg = encAlg;
	}
	public String getEncryptedBy() {
		return encryptedBy;
	}
	public void setEncryptedBy(String encryptedBy) {
		this.encryptedBy = encryptedBy;
	}
	public String getEncryptorContact() {
		return encryptorContact;
	}
	public void setEncryptorContact(String encryptorContact) {
		this.encryptorContact = encryptorContact;
	}
}
