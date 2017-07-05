package de.uni.stuttgart.iaas.securecsar.processor;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import de.uni.stuttgart.iaas.securecsar.info.Artifact;
import de.uni.stuttgart.iaas.securecsar.info.Constant;
import de.uni.stuttgart.iaas.securecsar.info.Csar;
import de.uni.stuttgart.iaas.securecsar.info.KeystoreEntryInfo;
import de.uni.stuttgart.iaas.securecsar.info.KeystoreInfo;
import de.uni.stuttgart.iaas.securecsar.info.SignatureEntry;
import de.uni.stuttgart.iaas.securecsar.info.SignatureFileInfo;
import de.uni.stuttgart.iaas.securecsar.info.response.DecryptCsarResponse;
import de.uni.stuttgart.iaas.securecsar.info.response.MessageType;
import de.uni.stuttgart.iaas.securecsar.info.response.ResponseMessage;
import de.uni.stuttgart.iaas.securecsar.info.response.VerifyCsarResponse;
import de.uni.stuttgart.iaas.securecsar.util.AlgorithmOptions.AsymetricKeyAlgo;
import de.uni.stuttgart.iaas.securecsar.util.AlgorithmOptions.SymetricKeyAlgo;
import de.uni.stuttgart.iaas.securecsar.util.StringUtil;

public class SecurityProcessor {
	private static final Logger LOGGER = LogManager.getLogger();

	public KeyStore generateKeyStore(boolean asymetric, String keystorePass, KeystoreEntryInfo keystoreEntryInfo) throws Exception {
		KeyStore ks = KeyStore.getInstance("JCEKS");
		ks.load(null, keystorePass.toCharArray());
		
		if (asymetric) {
			AsymetricKeyAlgo myKeyAlgo = AsymetricKeyAlgo.valueOf(keystoreEntryInfo.getKeyalg());
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keystoreEntryInfo.getKeyalg(), myKeyAlgo.getProvider());
			SecureRandom random = SecureRandom.getInstance(Constant.RANDOM_GEN_SCHEME, Constant.SECURITY_PROVIDER);
			keyGen.initialize(keystoreEntryInfo.getKeysize(), random);
			KeyPair keyPair = keyGen.generateKeyPair();
			Certificate cert = generateCertificate(keystoreEntryInfo.getCertificateInfo(), keyPair, keystoreEntryInfo.getKeyalg());
			PrivateKeyEntry entry = new PrivateKeyEntry(keyPair.getPrivate(), new Certificate[] { cert });
			ks.setEntry(keystoreEntryInfo.getAliasName(), entry, new KeyStore.PasswordProtection(keystoreEntryInfo.getAliasPass().toCharArray()));
		} else {
			SymetricKeyAlgo myKeyAlgo = SymetricKeyAlgo.valueOf(keystoreEntryInfo.getKeyalg());
			KeyGenerator KeyGen = KeyGenerator.getInstance(keystoreEntryInfo.getKeyalg(), myKeyAlgo.getProvider());
			KeyGen.init(keystoreEntryInfo.getKeysize());
			SecretKey mySecretKey = KeyGen.generateKey();
			KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(mySecretKey);
			ks.setEntry(keystoreEntryInfo.getAliasName(), skEntry, new KeyStore.PasswordProtection(keystoreEntryInfo.getAliasPass().toCharArray()));
		}
		
		return ks;
	}

	/**
	 * Create a self signed certificate. As it is a self signed certificate, So
	 * Public key in certificate as well as private key (should be CA private
	 * key), comes from KeyPair itself.
	 * 
	 * @param cert
	 * @param keyPair
	 * @return CertificateInfo
	 */
	public Certificate generateCertificate(de.uni.stuttgart.iaas.securecsar.info.CertificateInfo certInfo, KeyPair keyPair, String keyAlg)
			throws Exception {
		AsymetricKeyAlgo myKeyAlgo = AsymetricKeyAlgo.valueOf(keyAlg);
		ContentSigner sigGen = new JcaContentSignerBuilder(certInfo.getSigalg()).setProvider(myKeyAlgo.getProvider()).build(keyPair.getPrivate());
		SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
		Date startDate = new Date(System.currentTimeMillis() - new Long(24).longValue() * 60 * 60 * 1000);
		Date endDate = new Date(System.currentTimeMillis() + new Long(certInfo.getValidity()).longValue() * 24 * 60 * 60 * 1000);
		// as self signed certificate so issuer and subject DN are same
		String issuerAndSubjectDN = generateDN(certInfo);
		
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(new X500Name(issuerAndSubjectDN),
				BigInteger.ONE, startDate, endDate, new X500Name(issuerAndSubjectDN), subPubKeyInfo);
		
		X509CertificateHolder x509v3CertificateHolder = x509v3CertificateBuilder.build(sigGen);
		return new JcaX509CertificateConverter().getCertificate(x509v3CertificateHolder);
	}

	public String generateDN(de.uni.stuttgart.iaas.securecsar.info.CertificateInfo certInfo) {
		String dn = "CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown";
		
		if (!StringUtil.isEmpty(certInfo.getFirstAndLastName())) {
			dn = dn.replaceFirst("CN=Unknown", "CN=" + certInfo.getFirstAndLastName());
		}
		
		if (!StringUtil.isEmpty(certInfo.getOrganizationalUnit())) {
			dn = dn.replaceFirst("OU=Unknown", "OU=" + certInfo.getOrganizationalUnit());
		}
		
		if (!StringUtil.isEmpty(certInfo.getOrganization())) {
			dn = dn.replaceFirst("O=Unknown", "O=" + certInfo.getOrganization());
		}
		
		if (!StringUtil.isEmpty(certInfo.getCity())) {
			dn = dn.replaceFirst("L=Unknown", "L=" + certInfo.getCity());
		}
		
		if (!StringUtil.isEmpty(certInfo.getState())) {
			dn = dn.replaceFirst("ST=Unknown", "ST=" + certInfo.getState());
		}
		
		if (!StringUtil.isEmpty(certInfo.getCountryCode())) {
			dn = dn.replaceFirst("C=Unknown", "C=" + certInfo.getCountryCode());
		}
		
		return dn;
	}
	
	public String generateDigest(String digestAlg, byte[] data) throws Exception {
		MessageDigest md = MessageDigest.getInstance(digestAlg);
		md.update(data);
		byte[] digest = md.digest();
		return Base64.getEncoder().encodeToString(digest);
	}
	
	public byte[] generateSignature(KeystoreInfo keystoreInfo, KeyStore keystore, String sigAlg, byte[] dataToSign) throws Exception{
		// Getting certificate chain, signing certificate, and private
		// key info from keystore
		Security.addProvider(new BouncyCastleProvider());
		Key key = keystore.getKey(keystoreInfo.getEntry().getAliasName(),keystoreInfo.getEntry().getAliasPass().toCharArray());
		PrivateKey privateKey = (PrivateKey) key;
		
		Signature signature = Signature.getInstance(sigAlg, "BC");
        signature.initSign(privateKey);
        signature.update(dataToSign);
        
        //Build CMS
        X509Certificate cert = (X509Certificate) keystore.getCertificate(keystoreInfo.getEntry().getAliasName());
        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        CMSTypedData msg = new CMSProcessableByteArray(signature.sign());
        certList.add(cert);
        Store certs = new JcaCertStore(certList);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(privateKey);
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(signer, cert));
        gen.addCertificates(certs);
        CMSSignedData sigData = gen.generate(msg, true);
		return sigData.toASN1Structure().getEncoded("DER");
	}
	
	/**
	 * This function updates manifest entries in csar with files digests
	 * This function expect there must be a manifest object created in CSAR
	 * @param digestAlg
	 * @param csar
	 * @throws Exception
	 */
	public void addManifestDigests(String digestAlg, Csar csar) throws Exception{
		Map<String, Attributes> manifestEntries = csar.getManifest().getEntries();
		CsarProcessor csarProcessor = new CsarProcessor();
		
		for (Artifact artifact: csar.getArtifacts()) {
			// We do not sign files in META-INF (TOSCA Metadata) folder
			if (artifact.isToSign() && !artifact.getName().contains(Constant.META_INF)) {
				String digest = generateDigest(digestAlg, artifact.getContent());
				artifact.setDigest(digest);
				Attributes manifestEntryAttributes = manifestEntries.get(artifact.getName());
				String digestAttrName = StringUtil.getManifestDigestAttrName(digestAlg);
				csarProcessor.removeExistingSignature(manifestEntries.get(artifact.getName()), digestAttrName);
				
				if (manifestEntryAttributes != null) {
					manifestEntryAttributes.putValue(digestAttrName, digest);
				} 
			}					
		}
	}
	
	public void decryptCsar(KeyStore keystore, KeystoreInfo keystoreInfo, Csar csar, DecryptCsarResponse response) throws Exception {
		Map<String, Attributes> manifestEntries = csar.getManifest().getEntries();
		CsarProcessor csarProcessor = new CsarProcessor();
		Set<Entry<String, Attributes>> manifestEntrySet = manifestEntries.entrySet();
		
 		for (Entry<String, Attributes> entry: manifestEntrySet) {
			Attributes entryAttrs = entry.getValue();
			String entryName = entry.getKey();
			String keyFrom = entryAttrs.getValue(Constant.MANIFEST_PRIVATE_KEY_FROM);
			// this entry needs to be decrypted
			if (!StringUtil.isEmpty(keyFrom)) {
				
				//decrypt using key in keystore
				if (Constant.MANIFEST_KEY_FROM_VALUE_KEYSTORE.equals(keyFrom)) {
					
					if (keystore != null) {
						try {
							Key key = keystore.getKey(keystoreInfo.getEntry().getAliasName(), keystoreInfo.getEntry().getAliasPass().toCharArray());
							Cipher decryptCipher = Cipher.getInstance(entryAttrs.getValue(Constant.MANIFEST_ENC_ALG_KEY_NAME));
							decryptCipher.init(Cipher.DECRYPT_MODE, key);
							Artifact entryArtifact = csarProcessor.getArtifactByName(csar.getArtifacts(), entryName);
						    byte[] decryptedData = decryptCipher.doFinal(entryArtifact.getContent());
						    entryArtifact.setContent(decryptedData);
						    
						    // deleting encryption information from manifest
						    Set<Object> keys = entryAttrs.keySet();
						    ArrayList<Object> attrsToDelete = new ArrayList<Object>();
						    for (Object attrKey: keys) {
						    	if (Constant.MANIFEST_PRIVATE_KEY_FROM.equals(attrKey.toString()) ||
						    		Constant.MANIFEST_ENC_ALG_KEY_NAME.equals(attrKey.toString()) ||
						    		Constant.MANIFEST_ENC_BY.equals(attrKey.toString()) ||
						    		Constant.MANIFEST_ENCRYPTOR_CONTACT.equals(attrKey.toString())) {
						    		attrsToDelete.add(attrKey);
						    	}
						    }
						    
						    for (Object attrKey: attrsToDelete) {
						    	entryAttrs.remove(attrKey);
						    }
						    
						    response.addResponseMsg(new ResponseMessage(MessageType.SUCCESS, entryName + " decrypted successfully."));
						} catch (UnrecoverableKeyException ex) {
							response.addResponseMsg(
								new ResponseMessage(MessageType.WARNING, "Could not decrypt artifact " + entryName
								+ " - The key in keystore cannot be recovered."));
							
							LOGGER.log(Level.DEBUG, ex);
						} catch (Exception ex) {
							response.addResponseMsg(
								new ResponseMessage(MessageType.WARNING, "Could not decrypt artifact " + entryName
								+ " - Please confirm that key provided is the same used to encrypt the CSAR."));
							
							LOGGER.log(Level.DEBUG, ex);
						}
					} else {
						response.addResponseMsg(
							new ResponseMessage(MessageType.WARNING, "Could not decrypt artifact " + entryName
							+ " because it needs keystore with secret key used to encrypt the artifact."));
					}
				} else {
					// othercases for example key from external system
					// exposed by url can be implemented accordingly at this place.
					response.addResponseMsg(
						new ResponseMessage(MessageType.WARNING, "Could not decrypt artifact " + entryName
						+ " Decryption service does not implement the method to get decryption key as specified in policy file."));
				}
			}
		}
	}
	
	public boolean verifyCsar(Csar csar, Manifest existingManifest, SignatureFileInfo sigFileInfo, byte[] sigBlockData, VerifyCsarResponse response) throws Exception {
		boolean verificationPass = true;
		
		try {
			CsarProcessor csarProcessor = new CsarProcessor();
			SecurityProcessor secProcessor = new SecurityProcessor();
			HashMap<String, SignatureEntry> sigEntries = sigFileInfo.getEntries();
			
			for (String entry: sigEntries.keySet()) {
				SignatureEntry sigEntryValue = sigEntries.get(entry);
				String digestKey = sigEntryValue.getName();
				Attributes manifestEntry = existingManifest.getAttributes(entry);
				
				if (manifestEntry != null) {
					String manifestDigest = manifestEntry.getValue(digestKey);
					Artifact entryArtifact = csarProcessor.getArtifactByName(csar.getArtifacts(), entry);
					
					if (entryArtifact == null) {
						response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VERIFICATION_ERROR_FILE_NOTFOUND_IN_CSAR.replace("?", entry)));
						verificationPass = false;
					} else {
						String digestAlgo = digestKey.split("-Digest")[0];
						String actualDigest = secProcessor.generateDigest(digestAlgo, entryArtifact.getContent());
						if (actualDigest.equals(manifestDigest)) {
							response.addResponseMsg(new ResponseMessage(MessageType.SUCCESS, Constant.VERIFICATION_SUCCESS_CONTENT_MATCH + entry));
						} else {
							response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VERIFICATION_ERROR_CONTENT_MISMATCH + entry));
							verificationPass = false;
						}
					}
				} else {
					response.addResponseMsg(new ResponseMessage(MessageType.SUCCESS, Constant.VERIFICATION_ERROR_MANIFEST_ENTRY_NOTFOUND.replace("?", entry)));
					verificationPass = false;
				}
			}
			
			if (sigFileInfo.getManifestDigest() != null && sigFileInfo.getManifestMainAttrDigest() != null) {
				// Generation of signature file from csar
				String digestAlg = sigFileInfo.getManifestDigest().getName().split("-Digest")[0];
				
				// We have to set sign flag for all the artifacts because we are generating new signature file with all the entries
				csar.setSignAllArtifacts(true);
				for (Artifact artifact: csar.getArtifacts()) {
					artifact.setToSign(true);
				}
				
				SignatureFileInfo newSigFileData = new SignatureFileInfo(Constant.META_INF + File.separator + sigFileInfo.getName(), digestAlg, csar);
				SignatureFileInfo newSigFileInfo = new SignatureFileInfo(sigFileInfo.getName(), newSigFileData.getData());
				
				if (!sigFileInfo.getManifestMainAttrDigest().getName().equals(newSigFileInfo.getManifestMainAttrDigest().getName()) ||
					!sigFileInfo.getManifestMainAttrDigest().getValue().equals(newSigFileInfo.getManifestMainAttrDigest().getValue())) {
					response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VERIFICATION_ERROR_MANIFEST_MAIN_MISMATCH));
					verificationPass = false;
				}
				
				if (!sigFileInfo.getManifestDigest().getName().equals(newSigFileInfo.getManifestDigest().getName()) ||
					!sigFileInfo.getManifestDigest().getValue().equals(newSigFileInfo.getManifestDigest().getValue())) {
					response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VERIFICATION_ERROR_MANIFEST_MISMATCH));
					verificationPass = false;
				}
			}
			
			Security.addProvider(new BouncyCastleProvider());

			CMSSignedData signedData = new CMSSignedData(sigBlockData);
			Store store = signedData.getCertificates(); 
			SignerInformationStore signers = signedData.getSignerInfos(); 

			Collection<SignerInformation> signerInfos = signers.getSigners(); 
			Iterator<SignerInformation> signerIterator = signerInfos.iterator(); 

			while (signerIterator.hasNext()) {
			    SignerInformation signer = (SignerInformation)signerIterator.next(); 
			    Collection certCollection = store.getMatches(signer.getSID()); 
			    Iterator certIt = certCollection.iterator(); 
			    X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next(); 
			    X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder); 
			    String signerContent = " (Issuer DN: " + signer.getSID().getIssuer().toString() + ")";
			    
			    if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert))) {
			    	response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VERIFICATION_ERROR_SIGBLOCK_FAILED + signerContent));
					verificationPass = false;
			    } else {
			    	response.addResponseMsg(new ResponseMessage(MessageType.SUCCESS, Constant.VERIFICATION_SUCCESS_SIGBLOCK + signerContent));
			    }
			}
		} catch (IOException ioex) {
			response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VERIFICATION_ERROR_CORRUPTED_SIGBLOCK));
		} catch (CMSException ioex) {
			response.addResponseMsg(new ResponseMessage(MessageType.ERROR, Constant.VERIFICATION_ERROR_CORRUPTED_SIGBLOCK));
		} catch (Exception ex) {
			throw ex;
		}
		
		return verificationPass;
	}
	
	/**
	 * This function go through each artifact needs to be encrypted. It
	 * encrypts the artifact and update manifest by adding its information in
	 * manifest.
	 * 
	 * @param keystore
	 * @param keystoreInfo
	 * @param encAlg
	 * @param csar
	 * @param keyFrom
	 * @throws Exception
	 */
	public void encryptCsar(String encryptedBy, String encryptorContact, KeyStore keystore, KeystoreInfo keystoreInfo, String encAlg, Csar csar, String keyFrom) throws Exception{
		Map<String, Attributes> manifestEntries = csar.getManifest().getEntries();
		CsarProcessor csarProcessor = new CsarProcessor();
		Key key = keystore.getKey(keystoreInfo.getEntry().getAliasName(), keystoreInfo.getEntry().getAliasPass().toCharArray());
		
		for (Artifact artifact: csar.getArtifacts()) {
			if (artifact.isToEncrypt()) {
				byte[] encData = encrypt(artifact.getContent(), key, encAlg);
				artifact.setContent(encData);
				Attributes manifestEntryAttributes = manifestEntries.get(artifact.getName());
				csarProcessor.removeExistingEncryption(manifestEntries.get(artifact.getName()));
				
				// adding encryption information in manifest entry
				if (manifestEntryAttributes != null) {
					if (!StringUtil.isEmpty(encryptorContact)) {
						manifestEntryAttributes.putValue(Constant.MANIFEST_ENCRYPTOR_CONTACT, encryptorContact);
					}
					
					if (!StringUtil.isEmpty(encryptedBy)) {
						manifestEntryAttributes.putValue(Constant.MANIFEST_ENC_BY, encryptedBy);
					}
					
					if (!StringUtil.isEmpty(keyFrom)) {
						manifestEntryAttributes.putValue(Constant.MANIFEST_PRIVATE_KEY_FROM, keyFrom);
					} else {
						manifestEntryAttributes.putValue(Constant.MANIFEST_PRIVATE_KEY_FROM, Constant.MANIFEST_KEY_FROM_VALUE_KEYSTORE);
					}
					
					manifestEntryAttributes.putValue(Constant.MANIFEST_ENC_ALG_KEY_NAME, encAlg);
				} 
			}					
		}
	}
	
	public byte[] encrypt(byte[] data, Key key, String encAlg) throws Exception {
	    Cipher encryptCipher = Cipher.getInstance(key.getAlgorithm());
	    encryptCipher.init(Cipher.ENCRYPT_MODE, key);
	    byte[] cipherData = encryptCipher.doFinal(data);
	    return cipherData;
	}
	
	/**
	 * This function updates manifest main version key name from old to new.
	 * For example from TOSCA-Meta-Version to Manifest-Version
	 * 
	 * @param manifest
	 * @param oldKeyName
	 * @param newKeyName
	 */
	public void updateManifestMainKey(Manifest manifest, String oldKeyName, String newKeyName) {
		Attributes manMainAttrs = manifest.getMainAttributes();
		
		if (manMainAttrs != null) {
			String manVer = manifest.getMainAttributes().getValue(oldKeyName);
			manifest.getMainAttributes().putValue(newKeyName, manVer);
			Set<Object> keys = manifest.getMainAttributes().keySet();
			Object verObjectRef = null;
			
			for (Object key: keys) {
				if (key.toString().equals(oldKeyName)) {
					verObjectRef = key;
				}
			}
			
			manifest.getMainAttributes().remove(verObjectRef);
		}
	} 
}
