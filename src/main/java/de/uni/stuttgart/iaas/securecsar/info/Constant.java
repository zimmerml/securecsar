package de.uni.stuttgart.iaas.securecsar.info;

public class Constant {
	public static final String META_INF = "TOSCA-Metadata";
	public static final String MENIFEST_FILE = "TOSCA.meta";
	public static final String MENIFEST_FILE_MAIN_VERSION_ENTRY = "TOSCA-Meta-Version";
	public static final String MENIFEST_FILE_WOKRING_MAIN_VERSION_ENTRY = "Manifest-Version";
	public static final String MANIFEST_ENTRY_POLICY_FILE_KEY = "SecureCSAR-Definitions";
	public static final String MANIFEST_ENC_BY = "Encrypted-By";
	public static final String MANIFEST_ENCRYPTOR_CONTACT = "Encryptor-Contact";
	public static final String MANIFEST_ENC_ALG_KEY_NAME = "Encryption-Algorithm";
	public static final String MANIFEST_PRIVATE_KEY_FROM = "Key-From";
	public static final String MANIFEST_KEY_FROM_VALUE_KEYSTORE = "KEYSTORE";
	public static final String CREATED_BY = "University of Stuttgart - IAAS Department";
	
	public static final String SIG_ALG_DEFAULT_1 = "SHA1withDSA";
	public static final String SIG_ALG_DEFAULT_2 = "SHA256withRSA";
	public static final String SIG_ALG_DEFAULT_3 = "SHA256withECDSA ";
	public static final String DEFAULT_ALIAS_NAME = "mykey";
	public static final int DEFAULT_CERTIFICATE_VALIDITY = 90;
	// creating key pair - We always use SUN provider
	public static final String SECURITY_PROVIDER = "SUN";
	// We always use PRNG random number generator with SHA1 hash
	public static final String RANDOM_GEN_SCHEME = "SHA1PRNG";
	public static final String VALIDATION_MSG_PROVIDE_CSAR_NAME = "Please provide CSAR name";
	public static final String VALIDATION_MSG_PROVIDE_CSAR = "Please provide CSAR";
	public static final String VALIDATION_MSG_PROVIDE_KS = "Please provide keystore";
	public static final String VALIDATION_MSG_PROVIDE_KS_NAME = "Please provide name for keystore";
	public static final String VALIDATION_MSG_PROVIDE_KS_PW = "Please provide password for keystore";
	public static final String VALIDATION_MSG_INVALID_ALIAS = "Given alias does not exists";
	public static final String VALIDATION_MSG_PROVIDE_KS_ENTRY = "Please provide information about keystore entry (alias, password)";
	public static final String VALIDATION_MSG_PROVIDE_KS_ENTRY_ALIAS = "Please provide keystore alias";
	public static final String VALIDATION_MSG_PROVIDE_KS_ENTRY_PW = "Please provide keystore alias password";
	public static final String VALIDATION_MSG_PROVIDE_KS_ENTRY_NAME = "Please provide keystore alias name";
	public static final String VALIDATION_MSG_INVALID_KEYALG = "Please provide key algorithm one of RSA, DSA, and AES";
	public static final String VALIDATION_MSG_INVALID_SIGALG = "Please provide signature algorithm one of MD2withRSA, MD5withRSA, SHA1withRSA, SHA256withRSA, SHA384withRSA, SHA512withRSA, or SHA1withDSA";
	public static final String VALIDATION_MSG_INVALID_ENCALG = "Please provide valid encryption algorithm";
	public static final String VALIDATION_MSG_INVALID_DIGESTALG = "Please provide digest algorithm SHA256";
	public static final String VALIDATION_MSG_INVALID_KEYSIZE_DSA = "Invalid keysize provided. This must range from 512 to 1024, and must be a multiple of 64.";
	public static final String VALIDATION_MSG_INVALID_KEYSIZE_RSA = "Invalid keysize provided. Any integer that is a multiple of 8, greater than or equal to 512.";
	public static final String VALIDATION_MSG_INVALID_KEYSIZE_AES = "Invalid keysize provided. Please provide key size one of 128, 192, or 256";
	public static final String VALIDATION_MSG_INVALID_KEYSIZE_DES = "Invalid keysize provided. Please provide key size one of 56, 112, or 158";
	public static final String RESPONSE_ERROR_MSG_UNEXPECTED_ERROR = "Unexpected error while processing request.";
	public static final String RESPONSE_ERROR_INVALID_POLICY_CONFIG = "SecureCSARTemplate is not defined correctly.";
	public static final String RESPONSE_ERROR_MISSING_POLCY_CONFIG = "SecureCSARTemplate is missing in CSAR or is not configured correctly at manifest " + MANIFEST_ENTRY_POLICY_FILE_KEY;
	public static final String VALIDATION_MSG_INVALID_CERT_SIGALG = "Please provide a valid signature algorithm for certificate";
	public static final String VALIDATION_MSG_UNCOMPLIANT_CERT_SIGALG = "Signature algorithm for certificate is not compliant with key algorithm";
	public static final String VALIDATION_MSG_UNCOMPLIANT_SIGALG = "Signature algorithm for CSAR signing is not compliant with key algorithm";
	public static final String VALIDATION_MSG_INVALID_SIGFILE = "Signature filename must consist of the following characters: A-Z, 0-9, _ or -";
	public static final String VALIDATION_MSG_SIGALG_NOTFOUND = "No signature algorithm found compliant with provided key algorithm";
	public static final String VALIDATION_MSG_UNCOMPLIANT_ENCALG = "Encryption Algorithm not compliant with key algorithm";
	public static final String VALIDATION_MSG_WRONGE_KEYSTORE_PW = "Invalid keystore password";
	public static final String VALIDATION_MSG_WRONG_ALIAS_PW = "Password for alias is incorrect";
	public static final String VALIDATION_MSG_INVALID_KEYSTORE = "Error while initializing provided keystore";
	public static final String VALIDATION_MSG_PROVIDE_SIG_NAME = "Please provide the name of the signature which you want to verify.";
	
	public static final String FILE_ENCODING = "UTF_8";
	
	public static final String VERIFICATION_ERROR_NO_SIGNATURE_FOUND = "No signature (.SF/ Signature Block) found in CSAR against the provided signature name ";
	public static final String VERIFICATION_ERROR_NO_MANIFEST_IN_CSAR = "No manifest file found in CSAR (CSAR is not signed)";
	public static final String VERIFICATION_SUCCESS_CONTENT_MATCH = "Content verification successful for file ";
	public static final String VERIFICATION_ERROR_CONTENT_MISMATCH = "Content mismatch found for file ";
	public static final String VERIFICATION_ERROR_FILE_NOTFOUND_IN_CSAR = "File ? is no longer in csar.";
	public static final String VERIFICATION_ERROR_MANIFEST_ENTRY_NOTFOUND = "file '?' not found in manifest. This means that the file was not part of CSAR when CSAR was signed.";
	public static final String VERIFICATION_ERROR_MANIFEST_MAIN_MISMATCH = "Manifest Main attribute mismatch.";
	
	public static final String VERIFICATION_ERROR_MANIFEST_MISMATCH = "Manifest file mismatch. This means content of CSAR have been changed. "
		+ "If digest of all the files are same then new files must have gotten added in csar after being signed.";
	
	public static final String VERIFICATION_ERROR_SIGBLOCK_FAILED = "Verification failed for signer ";
	public static final String VERIFICATION_SUCCESS_SIGBLOCK = "Signature of CSAR verified successfully";
	public static final String VERIFICATION_ERROR_CORRUPTED_SIGBLOCK = "Cannot read signature. It looks corrupted.";
	public static final String CONFIG_FILE_NAME = "config.properties";
}
