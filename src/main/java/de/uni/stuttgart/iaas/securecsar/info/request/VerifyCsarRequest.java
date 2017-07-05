package de.uni.stuttgart.iaas.securecsar.info.request;

public class VerifyCsarRequest {
	private byte[] csar;
	private String sigfile;
	
	public byte[] getCsar() {
		return csar;
	}
	public void setCsar(byte[] csar) {
		this.csar = csar;
	}
	public String getSigfile() {
		return sigfile;
	}
	public void setSigfile(String sigfile) {
		this.sigfile = sigfile;
	}
}
