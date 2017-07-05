package de.uni.stuttgart.iaas.securecsar.info;

public class Artifact {
	private String name;
	private byte[] content;
	private String digest;
	private boolean toSign;
	private boolean toEncrypt;
	
	public Artifact () {
		
	}
	
	public Artifact(String name, byte[] content) {
		this.name = name;
		this.content = content;
	}
	
	public Artifact(String name) {
		this.name = name;
	}
	
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public byte[] getContent() {
		return content;
	}
	public void setContent(byte[] content) {
		this.content = content;
	}
	public String getDigest() {
		return digest;
	}
	public void setDigest(String digest) {
		this.digest = digest;
	}
	public boolean isToSign() {
		return toSign;
	}
	public void setToSign(boolean toSign) {
		this.toSign = toSign;
	}
	public boolean isToEncrypt() {
		return toEncrypt;
	}
	public void setToEncrypt(boolean toEncrypt) {
		this.toEncrypt = toEncrypt;
	}
}
