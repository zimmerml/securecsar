package de.uni.stuttgart.iaas.securecsar.processor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.uni.stuttgart.iaas.securecsar.info.Artifact;
import de.uni.stuttgart.iaas.securecsar.info.Constant;
import de.uni.stuttgart.iaas.securecsar.info.Csar;
import de.uni.stuttgart.iaas.securecsar.info.PolicyInfo;

public class CsarProcessor {
	
	private static final Logger LOGGER = LogManager.getLogger();
	
	/**
	 * This funcion marks an artifact sign flag based on policy file
	 * If the artifact cannot be found in csar. It sets warning message
	 * in response object. Warning is also set if policy file mentions an
	 * artifact in META-INF folder or TOSCA meta folder.
	 * @param csar
	 * @param policyInfo
	 */
	public void setSignFlagOfArtifacts(Csar csar, PolicyInfo policyInfo) {
		if (policyInfo.isSignAllArtifacts()) {
			csar.setSignAllArtifacts(true);
		}
		
		for (Artifact artifact: csar.getArtifacts()) {
			if (policyInfo.isSignAllArtifacts() ||
				policyInfo.getArtifactsToSign().contains(artifact.getName()))
				artifact.setToSign(true);
		}
	}
	
	/**
	 * This funcion marks an artifact encryption flag based on policy file
	 * If the artifact cannot be found in csar. It sets warning message
	 * in response object. Warning is also set if policy file mentions an
	 * artifact in META-INF folder or TOSCA meta folder.
	 * @param csar
	 * @param policyInfo
	 */
	public void setEncFlagOfArtifacts(Csar csar, PolicyInfo policyInfo) {
		for (Artifact artifact: csar.getArtifacts()) {			
			if (policyInfo.isEncryptAllArtifacts() ||
				policyInfo.getArtifactsToEncrypt().contains(artifact.getName()))
				artifact.setToEncrypt(true);
		}
	}
	
	public Artifact getArtifactByName(Csar csar, String artifactName) {
		Artifact myArtifact = null;
		
		for (Artifact artifact: csar.getArtifacts()) {
			if (artifactName.equals(artifact.getName())) {
				myArtifact = artifact;
			}
		}
		
		return myArtifact;
	}

	public ArrayList<Artifact> getArtifactContainsName(Csar csar, String artifactName) {
		ArrayList<Artifact> artifacts = new ArrayList<Artifact>();
		
		for (Artifact artifact: csar.getArtifacts()) {
			if (artifact.getName().contains(artifactName)) {
				artifacts.add(artifact);			
			}
		}
		
		return artifacts;
	}
	
	public void removeExistingSignature(Attributes manifestEntryAttributes, String digestAttrName) {
		ArrayList<String> attrToDelete = new ArrayList<String>();
		
		if (manifestEntryAttributes != null) {
			Set<Object> attributeNames = manifestEntryAttributes.keySet();
			for (Object attributesName : attributeNames) {
				String attributeNameString = attributesName.toString();
				if (attributeNameString.equals(digestAttrName)) {
					attrToDelete.add(attributeNameString);
				}
			}
		}
		
		for (String attr: attrToDelete) {
			manifestEntryAttributes.remove(attr);
		}
	}
	
	public void removeExistingEncryption(Attributes manifestEntryAttributes) {
		ArrayList<String> attrToDelete = new ArrayList<String>();
		
		if (manifestEntryAttributes != null) {
			Set<Object> attributeNames = manifestEntryAttributes.keySet();
			for (Object attributesName : attributeNames) {
				String attributeNameString = attributesName.toString();
				if (attributeNameString.equals(Constant.MANIFEST_ENC_ALG_KEY_NAME) ||
					attributeNameString.equals(Constant.MANIFEST_PRIVATE_KEY_FROM)) {
					attrToDelete.add(attributeNameString);
				}
			}
		}
		
		for (String attr: attrToDelete) {
			manifestEntryAttributes.remove(attr);
		}
	}
	
	/**
	 * This function creates java.util.jar.Manifest object from byte[] contents
	 * of manifest in csar. It removes all entries in manifest which do not have corrosponding file
	 * in csar. And if a file exist and entry does not, then this function adds this new entry
	 * in manifest file.
	 * 
	 * @param manifestContent
	 * @param artifacts
	 * @return
	 * @throws Exception
	 */
	public Manifest createManifest(byte[] manifestContent, ArrayList<Artifact> artifacts) throws Exception{
		ByteArrayInputStream manifestInputstream = null;
		Manifest manifest = null;
		
		try {
			if (manifestContent == null) {
				// create new  manifest
		        StringBuffer sbuf = new StringBuffer();
		        sbuf.append(Constant.MENIFEST_FILE_MAIN_VERSION_ENTRY + ": 1.0\r\n");
		        sbuf.append("CSAR-Version: 1.0\r\n");
		        sbuf.append("Created-By: " + Constant.CREATED_BY + "\r\n\r\n");
		        manifestInputstream = new ByteArrayInputStream(sbuf.toString().getBytes("UTF-8"));
			} else {
				manifestInputstream = new ByteArrayInputStream(manifestContent);
			}
			
			manifest = new Manifest(manifestInputstream);

			// Replace TOSCA specific Main version with Manifest standard version key name
			// We have to do this because java Manifest only works with Manifest-Version name
			// This should be replaced by Constant.MENIFEST_FILE_MAIN_VERSION_ENTRY at the time of writing
			SecurityProcessor securityProcessor = new SecurityProcessor();
			securityProcessor.updateManifestMainKey(manifest, Constant.MENIFEST_FILE_MAIN_VERSION_ENTRY, Constant.MENIFEST_FILE_WOKRING_MAIN_VERSION_ENTRY);
			
			// Getting all entries in manifest for processing
			Map<String, Attributes> manifestEntries = manifest.getEntries();
			Object[] manifestKeys = manifestEntries.keySet().toArray();
			
			// removing any entry in manifest which do not have actual file in CSAR
			for (Object key: manifestKeys) {
				boolean actualFileExist = false;
				
				for (Artifact artifact: artifacts) {
					if (key.toString().equals(artifact.getName())) {
						actualFileExist = true;
					}
				}
				
				if (!actualFileExist) {
					LOGGER.debug("Removing entry: " + key);
					manifestEntries.remove(key);
				}
			}
			
			// adding new entries in manifest (if does not exist already against actual file in csar)
			for (Artifact artifact: artifacts) {
				// files in META-INF or TOSCA META directory are not included in manifest
				if (!manifestEntries.containsKey(artifact.getName()) &&
					!artifact.getName().contains(Constant.META_INF)) {
					if (!artifact.getName().endsWith("/") && !artifact.getName().endsWith("\\")) {
						manifestEntries.put(artifact.getName(), new Attributes());
					}
				}
			}
		} catch (Exception ex) {
			throw ex;
		} finally {
			if (manifestInputstream != null) {
				manifestInputstream.close();
			}
		}
		
		return manifest;
	}
	
	/**
	 * This function convert a manifest into an array of bytes
	 * We can also specify if we want to update manifest main key name
	 * @param manifest
	 * @param replaceMainEntry
	 * @param oldKeyName
	 * @param newKeyName
	 * @return
	 * @throws Exception
	 */
	public byte[] serializeManifest(Manifest manifest, boolean replaceMainEntry, String oldKeyName, String newKeyName) throws Exception {
		ByteArrayOutputStream baos = null;
		byte[] manifestBytes = null;
		
		try {
			baos = new ByteArrayOutputStream();
			manifest.write(baos);
			baos.close();
			String manifestString = new String(baos.toByteArray(), "UTF-8");
			
			if (replaceMainEntry) {
				manifestString = manifestString.replace(oldKeyName, newKeyName);
			}
			
			manifestBytes = manifestString.getBytes("UTF-8");
		} catch (Exception ex) {
			throw ex;
		} finally {
			if (baos != null) {
				baos.close();
			}
		}
		
		return manifestBytes;
	}
	
	public Artifact getArtifactByName(ArrayList<Artifact> artifacts, String name) {
		for (Artifact artifact: artifacts) {
			if (name.equals(artifact.getName())) {
				return artifact;
			}
		}
		
		return null;
	}
	
	/**
	 * This function generate .csar file bytes using CSAR object content
	 * @return
	 */
	public byte[] generateCsar(Csar csar) throws Exception{
		byte[] csarBytes = null;
		ByteArrayOutputStream bos = null;
		ZipArchiveOutputStream zipArhchiveOs = null;
		
		try {
			bos = new ByteArrayOutputStream();
			zipArhchiveOs = new ZipArchiveOutputStream(bos);

			// adding all artifacts (these artifacts doesn't 
			// include manifest file, newly created SF and signature block files)
			for (Artifact artifact: csar.getArtifacts()) {
				ZipArchiveEntry entry = new ZipArchiveEntry(artifact.getName());
				zipArhchiveOs.putArchiveEntry(entry);
				zipArhchiveOs.write(artifact.getContent());
				zipArhchiveOs.closeArchiveEntry();
			}
			
			// adding manifest file
			ZipArchiveEntry entry = new ZipArchiveEntry(Constant.META_INF + File.separator + Constant.MENIFEST_FILE);
			zipArhchiveOs.putArchiveEntry(entry);
			zipArhchiveOs.write(new CsarProcessor().serializeManifest(csar.getManifest(), true, "Manifest-Version", Constant.MENIFEST_FILE_MAIN_VERSION_ENTRY));
			zipArhchiveOs.closeArchiveEntry();
			
			// adding signature file
			if (csar.getSigFileInfo() != null) {
				entry = new ZipArchiveEntry(csar.getSigFileInfo().getName());
				zipArhchiveOs.putArchiveEntry(entry);
				zipArhchiveOs.write(csar.getSigFileInfo().getData());
				zipArhchiveOs.closeArchiveEntry();
			}
			
			if (csar.getSigBlockInfo() != null) {
				// adding signature block file
				entry = new ZipArchiveEntry(csar.getSigBlockInfo().getName());
				zipArhchiveOs.putArchiveEntry(entry);
				zipArhchiveOs.write(csar.getSigBlockInfo().getData());
				zipArhchiveOs.closeArchiveEntry();

			}
			
			// closing (not only flushing) to make all the bytes flushed to byte array (otherwise unexpected EOF when extracting)
			zipArhchiveOs.close();
			bos.close();
			csarBytes = bos.toByteArray();
		} catch (Exception ex) {
			throw ex;
		} finally {
			if (zipArhchiveOs != null) {
				zipArhchiveOs.close();
			}
			
			if (bos != null) {
				bos.close();
			}
		}
		
		return csarBytes;
	}
}