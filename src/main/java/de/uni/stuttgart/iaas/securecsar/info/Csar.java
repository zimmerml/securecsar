package de.uni.stuttgart.iaas.securecsar.info;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.jar.Manifest;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.uni.stuttgart.iaas.securecsar.processor.CsarProcessor;
import de.uni.stuttgart.iaas.securecsar.util.StringUtil;

public class Csar {
	
	private static final Logger LOGGER = LogManager.getLogger();
	
	public Csar(String csarName, byte[] csarData, String sigFileName, String sigBlockName, boolean addManifest) throws Exception{
		init(csarName, csarData, sigFileName, sigBlockName, addManifest);
	}
	
	private String name;
	private Manifest manifest;
	private ArrayList<Artifact> artifacts;
	private SignatureFileInfo sigFileInfo;
	private SignatureBlockInfo sigBlockInfo;
	private boolean signAllArtifacts;
	
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}

	public Manifest getManifest() {
		return manifest;
	}
	public void setManifest(Manifest manifest) {
		this.manifest = manifest;
	}
	
	public ArrayList<Artifact> getArtifacts() {
		return artifacts;
	}
	public void setArtifacts(ArrayList<Artifact> artifacts) {
		this.artifacts = artifacts;
	}
	
	public SignatureFileInfo getSigFileInfo() {
		return sigFileInfo;
	}
	public void setSigFileInfo(SignatureFileInfo sigFileInfo) {
		this.sigFileInfo = sigFileInfo;
	}
	public SignatureBlockInfo getSigBlockInfo() {
		return sigBlockInfo;
	}
	public void setSigBlockInfo(SignatureBlockInfo sigBlockInfo) {
		this.sigBlockInfo = sigBlockInfo;
	}
	public boolean isSignAllArtifacts() {
		return signAllArtifacts;
	}
	public void setSignAllArtifacts(boolean signAllArtifacts) {
		this.signAllArtifacts = signAllArtifacts;
	}
	
	/**
	 * This function initialize CSAR object. if sigFileName and sigBlockName are given,
	 * it checks against them, and does not add them in artifacts because we want
	 * to override them with new signatures.
	 * 
	 * @param csarName
	 * @param csarData
	 * @param sigFileName
	 * @param sigBlockName
	 * @throws Exception
	 */
	private void init(String csarName, byte[] csarData, String sigFileName, String sigBlockName, boolean addManifest) throws Exception{
		CsarProcessor csarProcessor = new CsarProcessor();
		this.name = csarName;
				
		if (csarData != null) {
			ZipFile zipFile = null;
			SeekableInMemoryByteChannel inMemoryByteChannel = null;
			this.artifacts = new ArrayList<Artifact>();

			try {
				inMemoryByteChannel = new SeekableInMemoryByteChannel(csarData);
				zipFile = new ZipFile(inMemoryByteChannel);
				Enumeration<ZipArchiveEntry> entries = zipFile.getEntries();
				String manifestNameWithForwardSlash = Constant.META_INF + "/" + Constant.MENIFEST_FILE;
				String manifestNameWithBackSlash = Constant.META_INF + "\\" + Constant.MENIFEST_FILE;
				byte[] manifestData = null;
				
				while (entries.hasMoreElements()) {
					ZipArchiveEntry archiveEntry = entries.nextElement();
					LOGGER.debug("Extracting file: " + archiveEntry.getName());
					InputStream inputStream = zipFile.getInputStream(archiveEntry);
					byte[] artifactContent = IOUtils.toByteArray(inputStream);

					if (manifestNameWithForwardSlash.equals(archiveEntry.getName()) || manifestNameWithBackSlash.equals(archiveEntry.getName())) {
						manifestData = artifactContent;
						
						if (addManifest) {
							this.artifacts.add(new Artifact(archiveEntry.getName(), artifactContent));
						}
					} else {
						// we dont want two same signatures in CSAR
						if (!StringUtil.isEmpty(sigFileName) || !StringUtil.isEmpty(sigBlockName)) {
							String sigFilNameWithForwardSlash = Constant.META_INF + "/" + sigFileName;
							String sigFileNameWithBackSlash = Constant.META_INF + "\\" + sigFileName;
							String sigBlockNameWithForwardSlash = Constant.META_INF + "/" + sigBlockName;
							String sigBlockNameWithBackSlash = Constant.META_INF + "\\" + sigBlockName;
							
							if (!archiveEntry.getName().equals(sigFilNameWithForwardSlash) && 
								!archiveEntry.getName().equals(sigFileNameWithBackSlash) &&
								!archiveEntry.getName().equals(sigBlockNameWithForwardSlash) &&
								!archiveEntry.getName().equals(sigBlockNameWithBackSlash)) {
								this.artifacts.add(new Artifact(archiveEntry.getName(), artifactContent));
							}
						} else {
							this.artifacts.add(new Artifact(archiveEntry.getName(), artifactContent));
						}
					}
				}
				
				this.manifest = csarProcessor.createManifest(manifestData, artifacts);
			} catch (Exception ex) {
				throw ex;
			} finally {
				if (zipFile != null) {
					zipFile.close();
				}
				
				if (inMemoryByteChannel != null) {
					inMemoryByteChannel.close();
				}
			}
		}
	}
}
