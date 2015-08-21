package cn.com.jit.platform.tools;

import java.util.HashMap;
import java.util.Map;

import cn.com.jit.cloud.common.Base64Utils;
import cn.com.jit.cloud.common.dao.MongoConfigDao;
import cn.com.jit.cloud.common.dao.MongoManager;
import cn.com.jit.cloud.common.signhp.policy.LoggerConfig;
import cn.com.jit.signhp.policy.CertConfig;
import cn.com.jit.signhp.policy.CertConfigList;

public class ConfigIniTools {

	public static void main(String[] args) throws Exception {
//		ConfigInitializer.initDatabases();

		buildLogConfig();
//		initCert();
	}

	// ******************************* 初始化的代码 ***************************
	private static final byte[]			RSAPRVKEY		= Base64Utils
																.decode("MIIChwIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAN3UC2JaHzXZs0/yl1BPZqzQXVEN1/7JK+cBIpjkP8ThnniRHuHUavTH8sbgEeVx5IxZoy7qZcy/2fWh3IB9GGz3xs2gCximRUpvJvEn8dUht+1wIXkYeVtFOgADXF5qJBeoXnOyxmxEZxIanYhbRRnKM/OjQNWRQPcvRUmB9+N1AgMBAAECgYEAoSmzc6tCTZ9y9Tyszn5BfICNq5vBN6z0popelnIOGn5I4hOdOjlX06uJKRAWMHrEr2tYcXd+qnkgY6NLTlaUbQx5K/NGR+tq9F3Yu6k2QHF9FKgaerR14eZvbI09t18xvq4NaMy+7P9T7MU8Zkr0iK+9vr7gAHzyeW3fuf2s+WkCQQDvsnFn7REUWh0Yi+8U4NAWgbzLmRJVYCsOc05Z6QNoLtwagfG9UFGgbuDNiS2f4/ThFGz+dDLpwEtsDAs3LBhnAkEA7Op5dyEkPU7p4+rXkU8OcYUFP1b0QfM00In3OGxEEPlczc9PGHxdIDTReT9DEVisMcTf1nQN7ut4F4WiZXgrwwJAS1mzINJ7fgReBStoOw35HDoomXBDPSeAIYjJ5qXDdmrUsliLH9Ix9tckQDiRaSQGBQOgx9TLdIQIsayPkgaAnQJBAMUMvJxeH1MyyIx97m/4ji3TEqs8+onD7CCrL8lpGy/3B75SeBoIjjhUVgn/mRvbYdU/R2GKQ3B9vvPpfUniKpsCQQCQrkHch/ByjazK+iTXMIVSqlVf/1wzy4CXbgmosC38q3WtqBkb6zeeT0f1jOzNeHa8mO8MHyv3UUYvqrO2LtEUoA0wCwYDVR0PMQQDAgAQ"
																		.getBytes());
	private static final byte[]			RSACERT			= Base64Utils
																.decode("MIICdjCCAd+gAwIBAgIIRTUCMF6AR3kwDQYJKoZIhvcNAQEFBQAwLDEPMA0GA1UEAxMGRGVtb0NBMQwwCgYDVQQKEwNKSVQxCzAJBgNVBAYTAkNOMB4XDTA1MDIyMjA5MjQ1OVoXDTE1MDIyMDA5MjQ1OVowTjEPMA0GA1UEAxMGbm9ybWFsMSAwHgYJKoZIhvcNAQkBFhFub3JtYWxAaml0LmNvbS5jbjEMMAoGA1UEChMDaml0MQswCQYDVQQGEwJjbjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA3dQLYlofNdmzT/KXUE9mrNBdUQ3X/skr5wEimOQ/xOGeeJEe4dRq9MfyxuAR5XHkjFmjLuplzL/Z9aHcgH0YbPfGzaALGKZFSm8m8Sfx1SG37XAheRh5W0U6AANcXmokF6hec7LGbERnEhqdiFtFGcoz86NA1ZFA9y9FSYH343UCAwEAAaN/MH0wHwYDVR0jBBgwFoAUdsXVe5XOMJnisd+HHGGmks4jrNkwLgYDVR0fBCcwJTAjoCGgH4YdaHR0cDovLzE5Mi4xNjguOS4xNDAvY3JsMS5jcmwwCwYDVR0PBAQDAgTwMB0GA1UdDgQWBBQjg4s/NfDWvy9vxxtnadm9yrMdPzANBgkqhkiG9w0BAQUFAAOBgQAVmjt09ohVynM72qeT0ZSyA+L8AGXPzwoF8nKn9+AqBGpijfyyhaXLqEVfXkVIDjJ7dgqce4a9TThIaDxCE5JUgDoS9gzfZ5w7IX0931QXHhkvml2dYTYuxXMOrlbB2iIh2l+FCZUQoeb1IkgjUXktUYwmnpf17uTA26b0tThXeA=="
																		.getBytes());
	private static final byte[]			SM2PRVKEY		= Base64Utils
																.decode("MGgCAQEEIGxKXh1iVi2b/i8sTXit+RuVzelL/nyVzz1lcJI05AVWA0EBYN4tP4Oeewlg8JF4wFsOxpm0GquKTbbNFd8anfxv0ufgtefESMnzneQSP0T7hjYC6SJc+5B4OuZnf6APdYWW0g=="
																		.getBytes());
	private static final byte[]			SM2CERT			= Base64Utils
																.decode("MIIBWTCB/qADAgECAghzLXF0KdzEljAMBggqgRzPVQGDdQUAMC8xCzAJBgNVBAYTAkNOMQwwCgYDVQQKDANKSVQxEjAQBgNVBAMMCVNNMkRlbW9DQTAeFw0xMzEwMjMwMTAzMDFaFw0xNDEwMjMwMTAzMDFaMDMxCzAJBgNVBAYTAkNOMQwwCgYDVQQKDANKSVQxFjAUBgNVBAMMDTIwMTMxMDIzLUdNMDIwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAARg3i0/g557CWDwkXjAWw7GmbQaq4pNts0V3xqd/G/S5+C158RIyfOd5BI/RPuGNgLpIlz7kHg65md/oA91hZbSMAwGCCqBHM9VAYN1BQADSAAwRQIgKlPvrauPMcg/M+evGUUJ+OhvZLznvvtkyKobCE1hGcECIQDl9fx8FZSJNznXc3g18VlbFMcqkmRzoMmK0PBGTwkcag=="
																		.getBytes());
	private static final MongoConfigDao	configDao		= new MongoConfigDao();
	private static final MongoManager	mongoManager	= new MongoManager();

	private static void initCert() {
		addChildren();
	}

	private static void addChildren() {
		mongoManager.dropCollection(configDao.getDbName(), CertConfig.class);
		for (CertConfig certConfig : initCertConfigList().getCertConfigList()) {
			configDao.saveOrUpdate(certConfig);
		}
	}

	private static CertConfigList initCertConfigList() {
		CertConfigList expected = new CertConfigList();
		expected.add(getRsaCertConfig());
		expected.add(getSm2CertConfig());
		return expected;
	}

	private static CertConfig getRsaCertConfig() {
		CertConfig config = new CertConfig();
		config.setCertID("rsa");
		config.setAliases("rsa1|rsa2|rsa3");
		config.setCert(RSACERT);
		config.setPrvKey(RSAPRVKEY);
		config.setDigestAlgorithm("SHA1");
		config.setSymmetricAlgorithm("DES3");
		config.getCertUseSet().setSignature(true);
		config.getCertUseSet().setVerify(true);
		config.setCanEncrypt(true);
		config.setSm2(false);
		return config;
	}

	private static CertConfig getSm2CertConfig() {
		CertConfig config = new CertConfig();
		config.setCertID("sm2");
		config.setAliases("sm21|sm22|sm23");
		config.setCert(SM2CERT);
		config.setPrvKey(SM2PRVKEY);
		config.setDigestAlgorithm("SM3");
		config.setSymmetricAlgorithm("SM4");
		config.getCertUseSet().setSignature(true);
		config.getCertUseSet().setVerify(true);
		config.setCanEncrypt(true);
		config.setSm2(true);
		return config;
	}

	private static void buildLogConfig() {
		mongoManager.dropCollection(configDao.getDbName(), LoggerConfig.class);
		LoggerConfig config = new LoggerConfig();
		Map<String, boolean[]> logMap = new HashMap<String, boolean[]>();
		logMap.put("signLogStatus", new boolean[] { false, true });
		logMap.put("verifyLogStatus", new boolean[] { false, true });
		logMap.put("envelopEnc", new boolean[] {false, true});
		logMap.put("envelopDec", new boolean[] {false, true});
		logMap.put("symmetricenc", new boolean[] {false, true});
		logMap.put("symmetricdec", new boolean[] {false, true});
		config.setLogMap(logMap);
		configDao.saveOrUpdate(config);
	}

}
