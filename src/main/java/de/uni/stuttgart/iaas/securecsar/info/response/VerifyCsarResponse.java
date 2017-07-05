package de.uni.stuttgart.iaas.securecsar.info.response;

public class VerifyCsarResponse extends Response {
	private boolean verificationSuccess;

	public boolean isVerificationSuccess() {
		return verificationSuccess;
	}

	public void setVerificationSuccess(boolean verificationSuccess) {
		this.verificationSuccess = verificationSuccess;
	}
}
