package de.uni.stuttgart.iaas.securecsar.info;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.jar.Attributes;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.uni.stuttgart.iaas.securecsar.processor.CsarProcessor;
import de.uni.stuttgart.iaas.securecsar.processor.SecurityProcessor;
import de.uni.stuttgart.iaas.securecsar.util.StringUtil;

public class SignatureFileInfo {
	private static final Logger LOGGER = LogManager.getLogger();
	
	private String name;
	private byte[] data;
	private SignatureEntry sigVersion;
	private SignatureEntry manifestMainAttrDigest;
	private SignatureEntry manifestDigest;
	private SignatureEntry createdBy;
	private HashMap<String, SignatureEntry> entries;
	
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public byte[] getData() {
		return data;
	}

	public void setData(byte[] data) {
		this.data = data;
	}

	public SignatureEntry getSigVersion() {
		return sigVersion;
	}

	public void setSigVersion(SignatureEntry sigVersion) {
		this.sigVersion = sigVersion;
	}

	public SignatureEntry getManifestMainAttrDigest() {
		return manifestMainAttrDigest;
	}

	public void setManifestMainAttrDigest(SignatureEntry manifestMainAttrDigest) {
		this.manifestMainAttrDigest = manifestMainAttrDigest;
	}

	public SignatureEntry getManifestDigest() {
		return manifestDigest;
	}

	public void setManifestDigest(SignatureEntry manifestDigest) {
		this.manifestDigest = manifestDigest;
	}

	public SignatureEntry getCreatedBy() {
		return createdBy;
	}

	public void setCreatedBy(SignatureEntry createdBy) {
		this.createdBy = createdBy;
	}

	public HashMap<String, SignatureEntry> getEntries() {
		return entries;
	}

	public void setEntries(HashMap<String, SignatureEntry> entries) {
		this.entries = entries;
	}

	/**
	 * This constructor create signature file from provided CSAR file
	 * @param name
	 * @param data
	 * @param digestAlg
	 * @param csar
	 */
	public SignatureFileInfo(String name, String digestAlg, Csar csar) throws Exception {
		byte[] sfContent = null;
		String digest = null;
		this.name = name;
		
		CsarProcessor csarProcessor = new CsarProcessor();
		SecurityProcessor securityProcessor = new SecurityProcessor();
		// Making Manifest-Main-Attributes and Manifest Attribute (SF Header)
		String sfHeader = "Signature-Version: 1.0\r\n";

		// Digeset of Manifest Main section and full manifest file (only if all artifacts are signed)
		if (csar.isSignAllArtifacts()) {
			byte[] manifestData = csarProcessor.serializeManifest(csar.getManifest(), true, "Manifest-Version", Constant.MENIFEST_FILE_MAIN_VERSION_ENTRY);
			String manifestDataString = new String(manifestData, "UTF-8");
			
			String manifestHeaderSection = manifestDataString.split("\r\n\r\n")[0];
			manifestHeaderSection = manifestHeaderSection + "\r\n\r\n";
			LOGGER.debug(manifestHeaderSection);
			digest = securityProcessor.generateDigest(digestAlg, manifestHeaderSection.getBytes("UTF-8"));
			sfHeader = sfHeader + StringUtil.getManifestDigestAttrName(digestAlg) + "-Manifest-Main-Attributes: " + digest + "\r\n";
			
			digest = securityProcessor.generateDigest(digestAlg, manifestDataString.getBytes("UTF-8"));
			sfHeader = sfHeader + StringUtil.getManifestDigestAttrName(digestAlg) + "-Manifest: " + digest + "\r\n";
		}
		
		sfHeader = sfHeader + "Created-By: " + Constant.CREATED_BY + "\r\n\r\n";;
		
		// Making SF body
		String sfBody = "";
		Map<String, Attributes> manAttrs = csar.getManifest().getEntries();
		Set<Entry<String, Attributes>> manEntries = manAttrs.entrySet();
		
		for(Entry<String, Attributes> entry: manEntries) {
			Artifact artifact = csarProcessor.getArtifactByName(csar.getArtifacts(), entry.getKey());
			if (artifact.isToSign()) {
				String manifestSection = "";
				String manifestSectionName = "Name: " + entry.getKey() + "\r\n";
				manifestSection = manifestSectionName;
				Attributes entryAttrs = entry.getValue();
				
				// adding attributes to manifest section
				if (entryAttrs != null) {
					Set<Entry<Object, Object>> attrEntrySet = entryAttrs.entrySet();
					
					for(Entry<Object, Object> attr: attrEntrySet) {
						String attribute = "";
						attribute = attr.getKey().toString() + ": " + attr.getValue().toString() + "\r\n";
						manifestSection = manifestSection + attribute;
					}
				}
				
				manifestSection = manifestSection + "\r\n";
				LOGGER.debug("MANIFEST SECTION:");
				LOGGER.debug(manifestSection);
				digest = securityProcessor.generateDigest(digestAlg, manifestSection.getBytes("UTF-8"));
				sfBody = sfBody + manifestSectionName;
				sfBody = sfBody + StringUtil.getManifestDigestAttrName(digestAlg) + ": " + digest + "\r\n\r\n";
			}
		}
		
		String sfContentString = sfHeader + sfBody;
		sfContent = sfContentString.getBytes("UTF-8");
		this.data = sfContent;
	}
	
	/**
	 * This constructor creates signaturefileinfo from provided byte array
	 * @param data
	 */
	public SignatureFileInfo(String name, byte[] data) throws Exception {
		this.name = name;
		String sigContent = new String(data, "UTF-8");
		String[] entryStrings = sigContent.split("\r\n\r\n");
		this.entries = new HashMap<>();
		
		for (String entryString: entryStrings) {
			// signature header entry
			if (entryString.contains("Signature-Version")) {
				String[] sigHeaderStrings = entryString.split("\r\n");
				
				String[] version = sigHeaderStrings[0].split(":");
				this.sigVersion = new SignatureEntry(version[0].trim(), version[1].trim());
				
				// this means all artifacts of csar are signed and signature file must have manifest digest and manifestmainattr digest entries
				if (sigHeaderStrings.length == 4) {
					String[] manifestMainDigest = sigHeaderStrings[1].split(":");
					this.manifestMainAttrDigest = new SignatureEntry(manifestMainDigest[0].trim(), manifestMainDigest[1].trim());
					
					String[] manifestDigest = sigHeaderStrings[2].split(":");
					this.manifestDigest = new SignatureEntry(manifestDigest[0].trim(), manifestDigest[1].trim());
					
					String[] created = sigHeaderStrings[3].split(":");
					this.createdBy = new SignatureEntry(created[0].trim(), created[1].trim());
				} else {
					String[] created = sigHeaderStrings[1].split(":");
					this.createdBy = new SignatureEntry(created[0].trim(), created[1].trim());
				}
			} else {
				String[] sigEntryStrings = entryString.split("\r\n");
				
				String[] nameString = sigEntryStrings[0].split(":");
				String[] digestString = sigEntryStrings[1].split(":");
				
				entries.put(nameString[1].trim(), new SignatureEntry(digestString[0].trim(), digestString[1].trim()));
			}
		}
	}
}
