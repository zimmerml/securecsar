package de.uni.stuttgart.iaas.securecsar.info;

public class KeystoreInfo {
	private String keystoreName;
	private String keystorePass;
	private byte[] jksFile;
	private KeystoreEntryInfo entry;
	
	public KeystoreInfo() {
	} 
	
	public KeystoreInfo(String keystoreName, String keystorePass, byte[] jksFile, KeystoreEntryInfo entry) {
		this.keystoreName = keystoreName;
		this.keystorePass = keystorePass;
		this.jksFile = jksFile;
		this.entry = entry;
	}

	public String getKeystoreName() {
		return keystoreName;
	}

	public void setKeystoreName(String keystoreName) {
		this.keystoreName = keystoreName;
	}

	public String getKeystorePass() {
		return keystorePass;
	}

	public void setKeystorePass(String keystorePass) {
		this.keystorePass = keystorePass;
	}

	public byte[] getJksFile() {
		return jksFile;
	}

	public void setJksFile(byte[] jksFile) {
		this.jksFile = jksFile;
	}

	public KeystoreEntryInfo getEntry() {
		return entry;
	}

	public void setEntry(KeystoreEntryInfo entry) {
		this.entry = entry;
	}
}
