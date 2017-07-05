package de.uni.stuttgart.iaas.securecsar.info;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

import org.apache.commons.configuration2.XMLConfiguration;
import org.apache.commons.configuration2.builder.BasicConfigurationBuilder;
import org.apache.commons.configuration2.builder.fluent.Parameters;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.commons.configuration2.io.FileHandler;
import org.apache.commons.configuration2.tree.xpath.XPathExpressionEngine;

public class PolicyInfo {
	ArrayList<String> artifactsToEncrypt;
	ArrayList<String> artifactsToSign;
	private boolean signAllArtifacts;
	private boolean encryptAllArtifacts;
	private String decryptionMode;
	
	public ArrayList<String> getArtifactsToEncrypt() {
		return artifactsToEncrypt;
	}
	public void setArtifactsToEncrypt(ArrayList<String> artifactsToEncrypt) {
		this.artifactsToEncrypt = artifactsToEncrypt;
	}
	public ArrayList<String> getArtifactsToSign() {
		return artifactsToSign;
	}
	public void setArtifactsToSign(ArrayList<String> artifactsToSign) {
		this.artifactsToSign = artifactsToSign;
	}
	public boolean isSignAllArtifacts() {
		return signAllArtifacts;
	}
	public void setSignAllArtifacts(boolean signAllArtifacts) {
		this.signAllArtifacts = signAllArtifacts;
	}
	public boolean isEncryptAllArtifacts() {
		return encryptAllArtifacts;
	}
	public void setEncryptAllArtifacts(boolean encryptAllArtifacts) {
		this.encryptAllArtifacts = encryptAllArtifacts;
	}
	public String getDecryptionMode() {
		return decryptionMode;
	}
	public void setDecryptionMode(String decryptionMode) {
		this.decryptionMode = decryptionMode;
	}
	public PolicyInfo () {
		
	} 
	
	/**
	 * Initialize PolicyInfo object based on content in policyArtifact
	 * @param policyArtifact
	 */
	public void init(Artifact policyArtifact) throws ConfigurationException, Exception {
		try
		{
			XMLConfiguration policyTemplateDef = new BasicConfigurationBuilder<>(XMLConfiguration.class).configure(new Parameters().xml().setExpressionEngine(new XPathExpressionEngine())).getConfiguration();
			FileHandler fh = new FileHandler(policyTemplateDef);
			fh.load(new ByteArrayInputStream(policyArtifact.getContent()));

			// getting encrypt csar policy
			try {
				String encAllArtifactString = policyTemplateDef.getString("tosca:PolicyTemplate[@id='EncryptCsarPolicy']/tosca:Properties/pp:EncryptCsarProperties/pp:EncryptAllArtifacts");
				
				if (encAllArtifactString == null || "false".equalsIgnoreCase(encAllArtifactString)) {
					this.encryptAllArtifacts = false;
				} else {
					this.encryptAllArtifacts = true;
				}
				
			} catch (NoSuchElementException ex) {}
			
			if (!this.encryptAllArtifacts) {
				try {
					List<Object> artifactObjs = policyTemplateDef.getList("tosca:PolicyTemplate[@id='EncryptCsarPolicy']/tosca:Properties/pp:EncryptCsarProperties/pp:ArtifactsToEncrypt/tosca:ArtifactReference/@reference");
					
					if (artifactObjs != null) {
						this.artifactsToEncrypt = new ArrayList<String>((List<String>)(List<?>)artifactObjs);
					}
				} catch (NoSuchElementException ex) {}
			}
			
			try {
				this.decryptionMode = policyTemplateDef.getString("tosca:PolicyTemplate[@id='EncryptCsarPolicy']/tosca:Properties/pp:EncryptCsarProperties/pp:DecryptionMode/pp:Name");
			} catch (NoSuchElementException ex) {}
			
			// getting sign csar policy
			try {
				String signAllArtifactString = policyTemplateDef.getString("tosca:PolicyTemplate[@id='SignCsarPolicy']/tosca:Properties/pp:SignCsarProperties/pp:SignAllArtifacts");
				
				if (signAllArtifactString == null || "false".equalsIgnoreCase(signAllArtifactString)) {
					this.signAllArtifacts = false;
				} else {
					this.signAllArtifacts = true;
				}
				
			} catch (NoSuchElementException ex) {}
			
			if (!this.signAllArtifacts) {
				try {
					List<Object> artifactObjs = policyTemplateDef.getList("tosca:PolicyTemplate[@id='SignCsarPolicy']/tosca:Properties/pp:SignCsarProperties/pp:ArtifactsToSign/tosca:ArtifactReference/@reference");
					
					if (artifactObjs != null) {
						this.artifactsToSign = new ArrayList<String>((List<String>)(List<?>)artifactObjs);
					}
				} catch (NoSuchElementException ex) {}
			}
		} catch(ConfigurationException cex) {
		    throw cex;
		} catch(Exception ex) {
		    throw ex;
		}
		
//		this.signAllArtifacts = true;
//		this.artifactsToSign = new ArrayList<String>();
//		this.artifactsToSign.add("nodetypes/http%3A%2F%2Fopentosca.org%2Fnodetypes/RaspbianJessie/appearance/bigIcon.png");
//		this.encryptAllArtifacts = false;
//		this.artifactsToEncrypt = new ArrayList<String>();
//		this.artifactsToEncrypt.add("nodetypes/http%3A%2F%2Fopentosca.org%2Fnodetypes/RaspbianJessie/appearance/bigIcon.png");
//		this.decryptionMode = "KEYSTORE";
	}
	
}
