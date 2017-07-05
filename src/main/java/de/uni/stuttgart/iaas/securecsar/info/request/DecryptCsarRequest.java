package de.uni.stuttgart.iaas.securecsar.info.request;

import de.uni.stuttgart.iaas.securecsar.info.KeystoreInfo;

public class DecryptCsarRequest {
	private byte[] csar;
	private String csarName;
	private KeystoreInfo keystoreInfo;
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
}
