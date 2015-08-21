package cn.com.jit.signhp.policy;

import cn.com.jit.ida.util.pki.encoders.Base64;
import cn.com.jit.platform.pki.SignHelper;

public class RuntimePolicyTestHelper {

	private static final byte[]	PRVKEY	= Base64.decode("MIIChwIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAN3UC2JaHzXZs0/yl1BPZqzQXVEN1/7JK+cBIpjkP8ThnniRHuHUavTH8sbgEeVx5IxZoy7qZcy/2fWh3IB9GGz3xs2gCximRUpvJvEn8dUht+1wIXkYeVtFOgADXF5qJBeoXnOyxmxEZxIanYhbRRnKM/OjQNWRQPcvRUmB9+N1AgMBAAECgYEAoSmzc6tCTZ9y9Tyszn5BfICNq5vBN6z0popelnIOGn5I4hOdOjlX06uJKRAWMHrEr2tYcXd+qnkgY6NLTlaUbQx5K/NGR+tq9F3Yu6k2QHF9FKgaerR14eZvbI09t18xvq4NaMy+7P9T7MU8Zkr0iK+9vr7gAHzyeW3fuf2s+WkCQQDvsnFn7REUWh0Yi+8U4NAWgbzLmRJVYCsOc05Z6QNoLtwagfG9UFGgbuDNiS2f4/ThFGz+dDLpwEtsDAs3LBhnAkEA7Op5dyEkPU7p4+rXkU8OcYUFP1b0QfM00In3OGxEEPlczc9PGHxdIDTReT9DEVisMcTf1nQN7ut4F4WiZXgrwwJAS1mzINJ7fgReBStoOw35HDoomXBDPSeAIYjJ5qXDdmrUsliLH9Ix9tckQDiRaSQGBQOgx9TLdIQIsayPkgaAnQJBAMUMvJxeH1MyyIx97m/4ji3TEqs8+onD7CCrL8lpGy/3B75SeBoIjjhUVgn/mRvbYdU/R2GKQ3B9vvPpfUniKpsCQQCQrkHch/ByjazK+iTXMIVSqlVf/1wzy4CXbgmosC38q3WtqBkb6zeeT0f1jOzNeHa8mO8MHyv3UUYvqrO2LtEUoA0wCwYDVR0PMQQDAgAQ");
	private static final byte[]	CERT	= Base64.decode("MIICdjCCAd+gAwIBAgIIRTUCMF6AR3kwDQYJKoZIhvcNAQEFBQAwLDEPMA0GA1UEAxMGRGVtb0NBMQwwCgYDVQQKEwNKSVQxCzAJBgNVBAYTAkNOMB4XDTA1MDIyMjA5MjQ1OVoXDTE1MDIyMDA5MjQ1OVowTjEPMA0GA1UEAxMGbm9ybWFsMSAwHgYJKoZIhvcNAQkBFhFub3JtYWxAaml0LmNvbS5jbjEMMAoGA1UEChMDaml0MQswCQYDVQQGEwJjbjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA3dQLYlofNdmzT/KXUE9mrNBdUQ3X/skr5wEimOQ/xOGeeJEe4dRq9MfyxuAR5XHkjFmjLuplzL/Z9aHcgH0YbPfGzaALGKZFSm8m8Sfx1SG37XAheRh5W0U6AANcXmokF6hec7LGbERnEhqdiFtFGcoz86NA1ZFA9y9FSYH343UCAwEAAaN/MH0wHwYDVR0jBBgwFoAUdsXVe5XOMJnisd+HHGGmks4jrNkwLgYDVR0fBCcwJTAjoCGgH4YdaHR0cDovLzE5Mi4xNjguOS4xNDAvY3JsMS5jcmwwCwYDVR0PBAQDAgTwMB0GA1UdDgQWBBQjg4s/NfDWvy9vxxtnadm9yrMdPzANBgkqhkiG9w0BAQUFAAOBgQAVmjt09ohVynM72qeT0ZSyA+L8AGXPzwoF8nKn9+AqBGpijfyyhaXLqEVfXkVIDjJ7dgqce4a9TThIaDxCE5JUgDoS9gzfZ5w7IX0931QXHhkvml2dYTYuxXMOrlbB2iIh2l+FCZUQoeb1IkgjUXktUYwmnpf17uTA26b0tThXeA==");

	public static SymmEncryptConfig getSymmEncryptConfig() {
		SymmEncryptConfig config = new SymmEncryptConfig();
		config.setAlgorithm("DES3");
		config.setFillStyle("ECB");
		config.setId("id1");
		config.setLength(128);
		config.setKeyStatus(true);
		SymmKey symmKey = new SymmKey();
		symmKey.setNumber("key.00000");
		symmKey.setKey(new String(Base64.encode(SignHelper.SYMMETRICKEY)));
		config.addSymmKey(symmKey);
		return config;
	}

	public static CertConfigList getCertConfigList() {
		CertConfigList expected = new CertConfigList();
		CertConfig config = new CertConfig();
		config.setCertID("certid");
		config.setAliases("alias1|alias2|alias3");
		config.setCert(CERT);
		config.setPrvKey(PRVKEY);
		config.setDigestAlgorithm("SHA1");
		config.setSymmetricAlgorithm("DES3");
		config.getCertUseSet().setSignature(true);
		config.getCertUseSet().setVerify(true);
		config.setCanEncrypt(true);
		expected.add(config);
		return expected;
	}

}
