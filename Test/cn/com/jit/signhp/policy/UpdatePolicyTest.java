package cn.com.jit.signhp.policy;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.com.jit.cloud.common.dao.MongoConfigDao;
import cn.com.jit.cloud.common.dao.MongoManager;
import cn.com.jit.cloud.common.signhp.policy.LoggerConfig;
import cn.com.jit.platform.pki.SignHelper;

public class UpdatePolicyTest {
	private static MongoConfigDao			configDao		= new MongoConfigDao();
	private static List<CertConfig>			oldCerts		= null;
	private static List<SymmEncryptConfig>	keys			= null;
	private static List<LicenseConfig>		licenses		= null;
	private static List<LoggerConfig>		loggerConfigs	= null;
	private static List<LdapConfig>			ldapConfigs		= null;
	private static List<CaConfig>			caConfigs		= null;
	private UpdatePolicy					updatePolicy	= new UpdatePolicy();
	private static MongoManager				mongoManager	= new MongoManager();

	@Test
	public void should_get_correct_result_when_get_certs() {
		CertConfig cert = getCertConfig();
		configDao.saveOrUpdate(cert);

		CertConfigList certList = updatePolicy.getCertConfigList();
		List<CertConfig> certs = certList.getCertConfigList();
		Assert.assertEquals(1, certs.size());
		Assert.assertEquals(cert, certs.get(0));
	}

	@Test
	public void should_get_correct_result_when_get_keys() {
		SymmEncryptConfig key = getSymmEncryptConfig();
		configDao.saveOrUpdate(key);

		List<SymmEncryptConfig> keyList = updatePolicy.getSymmEncConfigList().getSymmEncConfigList();
		Assert.assertEquals(1, keyList.size());
		Assert.assertEquals(key, keyList.get(0));
	}

	@Test
	public void should_get_correct_result_when_get_license() {
		LicenseConfig license = getLicenseConfig();
		configDao.saveOrUpdate(license);
		Assert.assertEquals(license, updatePolicy.getLicenseConfig());
	}

	@Test
	public void should_get_correct_result_when_get_logger_config() {
		LoggerConfig loggerConfig = getLoggerConfig();
		configDao.saveOrUpdate(loggerConfig);
		Assert.assertEquals(loggerConfig, updatePolicy.getLoggerConfig());
	}

	@Test
	public void should_get_correct_result_when_get_ldap_config() {
		LdapConfig ldapConfig = getLdapConfig();
		configDao.saveOrUpdate(ldapConfig);

		List<LdapConfig> ldapConfigList = updatePolicy.getLdapConfigList().getLdapConfigList();
		Assert.assertEquals(1, ldapConfigList.size());
		Assert.assertEquals(ldapConfig, ldapConfigList.get(0));
	}

	@Test
	public void should_get_correct_result_when_get_ca() {
		CaConfig caConfig = getCaConfig();
		configDao.saveOrUpdate(caConfig);

		List<CaConfig> caConfigList = updatePolicy.getCaConfigList().getCaConfigList();
		Assert.assertEquals(1, caConfigList.size());
		Assert.assertEquals(caConfig, caConfigList.get(0));
	}

	private CaConfig getCaConfig() {
		CaConfig ca = new CaConfig();
		ca.setId("9521");
		ca.setCert(SignHelper.SIGN_CERT);
		ca.setCheckType(0);
		return ca;
	}

	private LdapConfig getLdapConfig() {
		LdapConfig ldapConfig = new LdapConfig();
		ldapConfig.setCaId("100");
		ldapConfig.setCertDownloadType(true);
		ldapConfig.setCertDownloadUrl("ldap://127.0.0.1:3306");
		return ldapConfig;
	}

	private LoggerConfig getLoggerConfig() {
		LoggerConfig logConfig = new LoggerConfig();
		logConfig.isAqs = false;
		Map<String, boolean[]> logMap = new HashMap<String, boolean[]>();
		logMap.put(LoggerConfig.SIGNLOGTYPE, new boolean[] { true, false });
		logMap.put(LoggerConfig.VSIGNLOGTYPE, new boolean[] { false, false });
		logMap.put(LoggerConfig.TSA_SIGN_LOG_STATUS, new boolean[] { true, true });
		logMap.put(LoggerConfig.TSA_VERIFY_LOG_STATUS, new boolean[] { true, false });
		logConfig.setLogMap(logMap);
		return logConfig;
	}

	private LicenseConfig getLicenseConfig() {
		LicenseConfig license = new LicenseConfig();
		license.setDate(new Date().toString());
		license.setEnvelop(true);
		license.setFinancial(true);
		license.setSignAture(true);
		license.setTimeSatmp(false);
		return license;

	}

	private SymmEncryptConfig getSymmEncryptConfig() {
		SymmEncryptConfig key = new SymmEncryptConfig();
		key.setAlgorithm("des");
		key.setFillStyle("ecb");
		key.setId("a");
		key.setKeyStatus(true);
		key.setLength(5);

		List<SymmKey> symmKey = new ArrayList<>();
		symmKey.add(new SymmKey("key1", "a00000"));
		symmKey.add(new SymmKey("key2", "a00001"));
		symmKey.add(new SymmKey("key3", "a00002"));
		symmKey.add(new SymmKey("key4", "a00003"));
		symmKey.add(new SymmKey("key5", "a00004"));
		key.setSymmKey(symmKey);
		return key;
	}

	private CertConfig getCertConfig() {
		CertConfig cert = new CertConfig();
		cert.setAliases("rsa");
		cert.setCanEncrypt(true);
		cert.getCertUseSet().setSignature(true);
		cert.getCertUseSet().setVerify(true);
		cert.setCert(SignHelper.SIGN_CERT);
		cert.setDigestAlgorithm("sha1");
		cert.setCertID("9527");
		cert.setPrvKey(SignHelper.PRVKEY);
		cert.setSm2(false);
		cert.setSymmetricAlgorithm("des");
		return cert;
	}

	@BeforeClass
	public static void before() {
		oldCerts = configDao.findAll(CertConfig.class);
		keys = configDao.findAll(SymmEncryptConfig.class);
		licenses = configDao.findAll(LicenseConfig.class);
		loggerConfigs = configDao.findAll(LoggerConfig.class);
		ldapConfigs = configDao.findAll(LdapConfig.class);
		caConfigs = configDao.findAll(CaConfig.class);
		
		clean();
	}
	
	private static void clean(){
		mongoManager.dropCollection(configDao.getDbName(),CertConfig.class);
		mongoManager.dropCollection(configDao.getDbName(),SymmEncryptConfig.class);
		mongoManager.dropCollection(configDao.getDbName(),LicenseConfig.class);
		mongoManager.dropCollection(configDao.getDbName(),LoggerConfig.class);
		mongoManager.dropCollection(configDao.getDbName(),LdapConfig.class);
		mongoManager.dropCollection(configDao.getDbName(),CaConfig.class);
	}

	@AfterClass
	public static void after() {
		// 测试之后清空数据库，保证没有冗余数据
		clean();

		if (oldCerts != null) {
			for (CertConfig o : oldCerts) {
				configDao.saveOrUpdate(o);
			}
		}

		if (keys != null) {
			for (SymmEncryptConfig o : keys) {
				configDao.saveOrUpdate(o);
			}
		}

		if (licenses != null) {
			for (LicenseConfig o : licenses) {
				configDao.saveOrUpdate(o);
			}
		}

		if (loggerConfigs != null) {
			for (LoggerConfig o : loggerConfigs) {
				configDao.saveOrUpdate(o);
			}
		}

		if (ldapConfigs != null) {
			for (LdapConfig o : ldapConfigs) {
				configDao.saveOrUpdate(o);
			}
		}

		if (caConfigs != null) {
			for (CaConfig o : caConfigs) {
				configDao.saveOrUpdate(o);
			}
		}
	}
}
