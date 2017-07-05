package de.uni.stuttgart.iaas.securecsar.util;

public class AlgorithmOptions {
	
	public enum DigestAlgo {
		MD2("MD2"),
		MD5("MD5"),
		SHA1("SHA-1"),
		SHA256("SHA-256"),
		SHA384("SHA-384"),
		SHA512("SHA-512");

	    private String name;

	    DigestAlgo(String name) {
	        this.name = name;
	    }

	    public String getName() {
	        return name;
	    }
	    
	    public static String getDefault() {
	        return SHA256.name;
	    }
	    
	    public static boolean exists(String checkAlgo) {

	        for (DigestAlgo algo : DigestAlgo.values()) {
	            if (algo.getName().equals(checkAlgo)) {
	                return true;
	            }
	        }

	        return false;
	    }
	}
	
	public enum SignatureAlgo {
		MD2withRSA("MD2withRSA"),
		MD5withRSA("MD5withRSA"),
		SHA1withRSA("SHA1withRSA"),
		SHA256withRSA("SHA256withRSA"),
		SHA384withRSA("SHA384withRSA"),
		SHA512withRSA("SHA512withRSA"),
		SHA1withDSA("SHA1withDSA");

	    private String name;

	    SignatureAlgo(String name) {
	        this.name = name;
	    }

	    public String getName() {
	        return name;
	    }
	    
	    public static String getDefault(String keyAlgo) {
	    	if ("DSA".equals(keyAlgo)) {
				return SHA1withDSA.name;
			} else if ("RSA".equals(keyAlgo)) {
				return SHA256withRSA.name;
			} else {
				return null;
			}
	    }
	    
	    public static boolean exists(String checkAlgo) {

	        for (SignatureAlgo algo : SignatureAlgo.values()) {
	            if (algo.getName().equals(checkAlgo)) {
	                return true;
	            }
	        }

	        return false;
	    }
	    
	    public boolean validate(String keyAlgo) {
	    	if (this.name().endsWith(keyAlgo)) {
	    		return true;
	    	}

	        return false;
	    }
	}
	
	public enum AsymetricKeyAlgo {
		DSA("DSA"),
		RSA("RSA");

	    private String name;
	    private String provider;
	    private int defaultKeysize;

	    AsymetricKeyAlgo(String name) {
	        this.name = name;
	        
	        if ("DSA".equals(name)) {
	        	provider = "SUN";
	        	defaultKeysize = 1024;
	        } else if ("RSA".equals(name)) {
	        	provider = "SunRsaSign";
	        	defaultKeysize = 2048;
	        }
	    }

	    public String getName() {
	        return name;
	    }
	    
	    public String getProvider() {
	        return provider;
	    }
	    
	    public int getDefaultKeysize() {
	        return defaultKeysize;
	    }
	    
	    public static String getDefault() {
	    	return DSA.name;
	    }
	    
	    public static boolean exists(String checkAlgo) {

	        for (AsymetricKeyAlgo algo : AsymetricKeyAlgo.values()) {
	            if (algo.getName().equals(checkAlgo)) {
	                return true;
	            }
	        }

	        return false;
	    }
	}
	
	public enum SymetricKeyAlgo {
		AES("AES"),
		DES("DES"),
		DESede("DESede");

	    private String name;
	    private String provider;
	    private int defaultKeysize;

	    SymetricKeyAlgo(String name) {
	        this.name = name;
	        
	        if ("AES".equals(name)) {
	        	provider = "SunJCE";
	        	defaultKeysize = 128;
	        } else if ("DES".equals(name)) {
	        	provider = "SunJCE";
	        	defaultKeysize = 56;
	        } else if ("DESede".equals(name)) {
	        	provider = "SunJCE";
	        	defaultKeysize = 112;
	        }
	    }

	    public String getName() {
	        return name;
	    }
	    
	    public String getProvider() {
	        return provider;
	    }
	    
	    public int getDefaultKeysize() {
	        return defaultKeysize;
	    }
	    
	    public static String getDefault() {
	    	return AES.name;
	    }
	    
	    public static boolean exists(String checkAlgo) {

	        for (SymetricKeyAlgo algo : SymetricKeyAlgo.values()) {
	            if (algo.getName().equals(checkAlgo)) {
	                return true;
	            }
	        }

	        return false;
	    }
	}
	
	public enum EncryptionAlgo {
		AES("AES"),
		DES("DES"),
		DESede("DESede");

	    private String name;

		EncryptionAlgo(String name) {
	        this.name = name;
	    }

	    public String getName() {
	        return name;
	    }
	    
	    public static String getDefault() {
	    	return AES.name;
	    }
	    
	    public static boolean exists(String checkAlgo) {

	        for (EncryptionAlgo algo : EncryptionAlgo.values()) {
	            if (algo.getName().equals(checkAlgo)) {
	                return true;
	            }
	        }

	        return false;
	    }
	    
	    public boolean validate(String keyAlgo) {
	    	if (this.name().endsWith(keyAlgo)) {
	    		return true;
	    	}

	        return false;
	    }
	}
}
