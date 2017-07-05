package de.uni.stuttgart.iaas.securecsar.validator;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.UnrecoverableKeyException;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.uni.stuttgart.iaas.securecsar.info.CertificateInfo;
import de.uni.stuttgart.iaas.securecsar.info.Constant;
import de.uni.stuttgart.iaas.securecsar.info.KeystoreEntryInfo;
import de.uni.stuttgart.iaas.securecsar.info.KeystoreInfo;
import de.uni.stuttgart.iaas.securecsar.info.request.SignCsarRequest;
import de.uni.stuttgart.iaas.securecsar.info.response.MessageType;
import de.uni.stuttgart.iaas.securecsar.info.response.ResponseMessage;
import de.uni.stuttgart.iaas.securecsar.info.response.SignCsarResponse;
import de.uni.stuttgart.iaas.securecsar.util.AlgorithmOptions.AsymetricKeyAlgo;
import de.uni.stuttgart.iaas.securecsar.util.AlgorithmOptions.DigestAlgo;
import de.uni.stuttgart.iaas.securecsar.util.AlgorithmOptions.SignatureAlgo;
import de.uni.stuttgart.iaas.securecsar.util.StringUtil;

public class SignCsarRequestValidator {

	private static final Logger LOGGER = LogManager.getLogger();
	
	// This function validates SignCsarRequest.
	// Incase validation fails, it sets respective message in
	// SignCsarResponse object and returns false.
	// This function also set default mandatory fields if not provided
	public boolean validate(SignCsarRequest request, SignCsarResponse response) throws Exception {
		InputStream iosForKeysstore = null;
		
		try {
			if (request.getKeystoreInfo() == null) {
				request.setKeystoreInfo(new KeystoreInfo());
				request.getKeystoreInfo().setEntry(new KeystoreEntryInfo());
				request.getKeystoreInfo().getEntry().setCertificateInfo(new CertificateInfo());
			} else if (request.getKeystoreInfo().getEntry() == null) {
				request.getKeystoreInfo().setEntry(new KeystoreEntryInfo());
				request.getKeystoreInfo().getEntry().setCertificateInfo(new CertificateInfo());
			} else if (request.getKeystoreInfo().getEntry().getCertificateInfo() == null) {
				request.getKeystoreInfo().getEntry().setCertificateInfo(new CertificateInfo());
			}
			
			if (request.getCsar() == null) {
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR,Constant.VALIDATION_MSG_PROVIDE_CSAR));
				return false;
			}
			
			if (StringUtil.isEmpty(request.getCsarName())) {
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_PROVIDE_CSAR_NAME));
				return false;
			}
			
			if (StringUtil.isEmpty(request.getKeystoreInfo().getKeystorePass())) {
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_PROVIDE_KS_PW));
				return false;
			}

			if (StringUtil.isEmpty(request.getKeystoreInfo().getEntry().getAliasName())) {
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR,Constant.VALIDATION_MSG_PROVIDE_KS_ENTRY_NAME));
				return false;
			}
			
			if (StringUtil.isEmpty(request.getKeystoreInfo().getEntry().getAliasPass())) {
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_PROVIDE_KS_ENTRY_PW));
				return false;
			}
			
			// Verifying if provided keystore credentials are correct and getting keyalg from keystore (Exceptions are caught for verification)
			if (request.getKeystoreInfo().getJksFile() != null) {
				iosForKeysstore = new ByteArrayInputStream(request.getKeystoreInfo().getJksFile());
				KeyStore keystore = KeyStore.getInstance("JCEKS");
				keystore.load(iosForKeysstore, request.getKeystoreInfo().getKeystorePass().toCharArray());
				Key key = keystore.getKey(request.getKeystoreInfo().getEntry().getAliasName(), request.getKeystoreInfo().getEntry().getAliasPass().toCharArray());
				
				if (key == null) {
					response.addResponseMsg(new ResponseMessage(MessageType.ERROR,Constant.VALIDATION_MSG_INVALID_ALIAS));
					return false;
				} else {
					request.getKeystoreInfo().getEntry().setKeyalg(key.getAlgorithm());
				}
			} else {
				// Request to create new create keystore - setting default values which are not provided
				// default aliasname
				if (StringUtil.isEmpty(request.getKeystoreInfo().getKeystoreName())) {
					response.addResponseMsg(new ResponseMessage(MessageType.ERROR,Constant.VALIDATION_MSG_PROVIDE_KS_NAME));
					return false;
				}
				
				if (StringUtil.isEmpty(request.getKeystoreInfo().getEntry().getAliasName())) {
					request.getKeystoreInfo().getEntry().setAliasName(Constant.DEFAULT_ALIAS_NAME);
				}
				
				if (StringUtil.isEmpty(request.getKeystoreInfo().getEntry().getKeyalg())) {
					// default key algorithm
					request.getKeystoreInfo().getEntry().setKeyalg(AsymetricKeyAlgo.getDefault());
				} else if (!AsymetricKeyAlgo.exists(request.getKeystoreInfo().getEntry().getKeyalg())) {
					response.addResponseMsg(new ResponseMessage(MessageType.ERROR,Constant.VALIDATION_MSG_INVALID_KEYALG));
					return false;
				}
				
				if (request.getKeystoreInfo().getEntry().getKeysize() == 0) {
					// default keysize (based on key algorithm)
					AsymetricKeyAlgo myKeyAlgo = AsymetricKeyAlgo.valueOf(request.getKeystoreInfo().getEntry().getKeyalg());
					if (myKeyAlgo != null) {
						request.getKeystoreInfo().getEntry().setKeysize(myKeyAlgo.getDefaultKeysize());
					}
				} else {
					if (request.getKeystoreInfo().getEntry().getKeyalg() == "DSA") {
						if (request.getKeystoreInfo().getEntry().getKeysize() < 512
							|| request.getKeystoreInfo().getEntry().getKeysize() > 1024
							|| request.getKeystoreInfo().getEntry().getKeysize() % 64 != 0) {
							response.addResponseMsg(
							new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_INVALID_KEYSIZE_DSA));
							return false;
						}
					} else if (request.getKeystoreInfo().getEntry().getKeyalg() == "RSA") {
						if (request.getKeystoreInfo().getEntry().getKeysize() < 512
							|| request.getKeystoreInfo().getEntry().getKeysize() % 8 != 0) {
							response.addResponseMsg(
							new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_INVALID_KEYSIZE_RSA));
							return false;
						}
					}
				}
				
				// default certificate validity
				if (request.getKeystoreInfo().getEntry().getCertificateInfo().getValidity() == 0) {
					request.getKeystoreInfo().getEntry().getCertificateInfo().setValidity(Constant.DEFAULT_CERTIFICATE_VALIDITY);
				}
				
				if (StringUtil.isEmpty(request.getKeystoreInfo().getEntry().getCertificateInfo().getSigalg())) {
					// default certificate signing algorithm
					String sigalg = StringUtil.getDigestAlgoCombination(request.getKeystoreInfo().getEntry().getKeyalg());
					
					if (StringUtil.isEmpty(sigalg)) {
						response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_SIGALG_NOTFOUND));
						return false;
					} else {
						request.getKeystoreInfo().getEntry().getCertificateInfo().setSigalg(sigalg);
					}
				} else if (!SignatureAlgo.exists(request.getKeystoreInfo().getEntry().getCertificateInfo().getSigalg())) {
					// certificate signature algorithm provided but is not valid
					response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_INVALID_CERT_SIGALG));
					return false;
				}
				
				// validation if certificate signature algorithm is compliant with key algorithm
				SignatureAlgo myCertSigAlo = SignatureAlgo.valueOf(request.getKeystoreInfo().getEntry().getCertificateInfo().getSigalg());
				if (myCertSigAlo == null || !myCertSigAlo.validate(request.getKeystoreInfo().getEntry().getKeyalg())) {
					response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_UNCOMPLIANT_CERT_SIGALG));
					return false;
				}
			}
			
			if (StringUtil.isEmpty(request.getDigestalg())) {
				// default digest algorithm
				request.setDigestalg(DigestAlgo.getDefault());
			} else {
				if (!DigestAlgo.exists(request.getDigestalg())) {
					response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_INVALID_DIGESTALG));
					return false;
				}
			}
			
			if (!StringUtil.isEmpty(request.getSigfile())) {
				//The characters in the file must come from the set a-zA-Z0-9_-. Only letters, numbers, underscore, and hyphen characters are allowed.
				String tempSigFile = request.getSigfile().toUpperCase();
				for (int j = 0; j < tempSigFile.length(); j++) {
					char c = tempSigFile.charAt(j);
				    if (!((c>= 'A' && c<= 'Z') || (c>= '0' && c<= '9') || (c == '-') || (c == '_'))) {
						response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_INVALID_SIGFILE));
				    	return false;
				    }
				}
			}
			
			// default signature algorithm (used to generate signature block)
			if (StringUtil.isEmpty(request.getSigalg())) {
				request.setSigalg(StringUtil.getDigestAlgoCombination(request.getKeystoreInfo().getEntry().getKeyalg()));
				
				if (StringUtil.isEmpty(request.getSigalg())) {
					response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_SIGALG_NOTFOUND));
					return false;
				}
			} else if (!SignatureAlgo.exists(request.getSigalg())) {
				// Signature algorithm provided but is not valid
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_INVALID_SIGALG));
				return false;
			}
			
			// Validation if signature algorithm is compliant with key algorithm or not
			SignatureAlgo mySigningSigAlgo = SignatureAlgo.valueOf(request.getSigalg());
			if (mySigningSigAlgo == null || !mySigningSigAlgo.validate(request.getKeystoreInfo().getEntry().getKeyalg())) {
				response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_UNCOMPLIANT_SIGALG));
				return false;
			}
			
			return true;
		} catch (IOException ex) {
			response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_WRONGE_KEYSTORE_PW));
			LOGGER.log(Level.DEBUG, ex);
			return false;
		} catch (UnrecoverableKeyException ex) {
			response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_WRONG_ALIAS_PW));
			LOGGER.log(Level.DEBUG, ex);
			return false;
		} catch (Exception ex) {
			response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VALIDATION_MSG_INVALID_KEYSTORE));
			throw ex;
		} finally {
			if (iosForKeysstore != null) {
				iosForKeysstore.close();
			}
		}
	}
}