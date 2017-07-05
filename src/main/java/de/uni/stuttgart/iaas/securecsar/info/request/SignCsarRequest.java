package de.uni.stuttgart.iaas.securecsar.info.request;

import de.uni.stuttgart.iaas.securecsar.info.KeystoreInfo;

public class SignCsarRequest {
	private byte[] csar;
	private String csarName;
	private KeystoreInfo keystoreInfo;
	private String sigalg;
	private String digestalg;
	private String sigfile;
	
	public SignCsarRequest() {
		
	}

	public KeystoreInfo getKeystoreInfo() {
		return keystoreInfo;
	}

	public void setKeystoreInfo(KeystoreInfo keystoreInfo) {
		this.keystoreInfo = keystoreInfo;
	}
	
	public String getSigalg() {
		return sigalg;
	}

	public void setSigalg(String sigalg) {
		this.sigalg = sigalg;
	}

	public String getDigestalg() {
		return digestalg;
	}

	public void setDigestalg(String digestalg) {
		this.digestalg = digestalg;
	}

	public String getSigfile() {
		return sigfile;
	}

	public void setSigfile(String sigfile) {
		this.sigfile = sigfile;
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
}
