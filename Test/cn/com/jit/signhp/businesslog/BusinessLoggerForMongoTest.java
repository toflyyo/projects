package cn.com.jit.signhp.businesslog;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import junit.framework.Assert;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.com.jit.cloud.common.dao.MongoLogDao;
import cn.com.jit.cloud.common.dao.MongoManager;
import cn.com.jit.cloud.common.log.entity.BusinessLog;
import cn.com.jit.ida.util.pki.PKIException;
import cn.com.jit.ida.util.pki.cert.X509Cert;
import cn.com.jit.platform.pki.SignHelper;

public class BusinessLoggerForMongoTest {
	
	private static String tb_business_log = "tb_business_log";
	private BusinessWriterForMongo logger = new BusinessWriterForMongo();
	private static MongoManager mongo = new MongoManager();
	private static MongoLogDao logDao = new MongoLogDao();
	
	@BeforeClass
	public static void before() {
		clean();
	}

	private static void clean() {
		mongo.dropCollection(logDao.getDbName(), tb_business_log);
	}

	@AfterClass
	public static void after() {
//		clean();
	}

	@Test
	public void should_success_when_save_p7sign_business_log() throws Exception {
		Map<String, Object> logMap = buildP7SignBusinessLog();
		logger.writeLogs(logMap);
		List<BusinessLog> logs = logDao.findAll(BusinessLog.class);
		Assert.assertNotNull(logs.get(0));
	}
	
	@Test
	public void should_success_when_save_p7verify_business_log() throws Exception {
		Map<String, Object> logMap = buildP7VerifyBusinessLog();
		logger.writeLogs(logMap);
		List<BusinessLog> logs = logDao.findAll(BusinessLog.class);
		Assert.assertNotNull(logs.get(0));
	}
	
	@Test
	public void should_success_when_save_p1sign_business_log() throws Exception {
		Map<String, Object> logMap = buildP1SignBusinessLog();
		logger.writeLogs(logMap);
		List<BusinessLog> logs = logDao.findAll(BusinessLog.class);
		Assert.assertNotNull(logs.get(0));
	}

	
	@Test
	public void should_success_when_save_p1verify_business_log() throws Exception {
		Map<String, Object> logMap = buildP1VerifyBusinessLog();
		logger.writeLogs(logMap);
		List<BusinessLog> logs = logDao.findAll(BusinessLog.class);
		Assert.assertNotNull(logs.get(0));
	}
	
	@Test
	public void should_success_when_save_encEnvelop_business_log() throws Exception {
		Map<String, Object> logMap = buildEncEnvelopBusinessLog();
		logger.writeLogs(logMap);
		List<BusinessLog> logs = logDao.findAll(BusinessLog.class);
		Assert.assertNotNull(logs.get(0));
	}
	
	@Test
	public void should_success_when_save_decEnvelop_business_log() throws Exception {
		Map<String, Object> logMap = buildDecEnvelopBusinessLog();
		logger.writeLogs(logMap);
		List<BusinessLog> logs = logDao.findAll(BusinessLog.class);
		Assert.assertNotNull(logs.get(0));
	}
	
	@Test
	public void should_success_when_save_error_log() {
		Map<String, Object> errors = buildErrorLog();
		logger.writeErrorLogs(errors, null, null);
		List<BusinessLog> logs = logDao.findAll(BusinessLog.class);
		Assert.assertNotNull(logs.get(0));
	}

	/**
	 * 准备p7签名业务日志数据
	 * @return logs
	 * @throws Exception
	 */
	private Map<String, Object> buildP7SignBusinessLog() throws Exception {
		X509Cert cert = new X509Cert(SignHelper.SIGN_CERT);
		Map<String, Object> logs = new LinkedHashMap<>();
		logs.put("CLIENT_IP", "127.0.0.1");
		logs.put("BUSINESS_TYPE", "P7Sign");
		logs.put("DIGEST_ALGORITHM", "sha1");
		logs.put("DIGEST_DATA", null);
		logs.put("SIGN_ALGORITHM", ("SHA1WITHRSA"));
		logs.put("SIGN_CERT_SUBJECT", cert.getSubject());
		logs.put("SIGN_CERTIFICATE", SignHelper.SIGN_CERT);
		logs.put("STATUS", LoggerEnum.SUCCESS_CN);
		logs.put("ACCESSED_TIME", new Date());
		logs.put("FINISHED_TIME", new Date());
		logs.put("SESSION_ID", "");
		logs.put("SIGNED_DATA", SignHelper.SIGN_ATTACH_RESULT);
		logs.put("SIGNED_DATA_TYPE", "P7Sign");
		logs.put("PLAIN_DATA", SignHelper.PLAIN);
		logs.put("PLAIN_TYPE", "0");
		return logs;
	}
	
	/**
	 * 准备p7验签业务日志数据
	 * @return logs
	 * @throws Exception
	 */
	private Map<String, Object> buildP7VerifyBusinessLog() throws Exception {
		X509Cert cert = new X509Cert(SignHelper.SIGN_CERT);
		Map<String, Object> logs = new LinkedHashMap<>();
		logs.put("CLIENT_IP", "127.0.0.1");
		logs.put("BUSINESS_TYPE", "verifyP7Sign");
		logs.put("DIGEST_ALGORITHM", "sha1");
		logs.put("DIGEST_DATA", null);
		logs.put("SIGN_ALGORITHM", ("SHA1WITHRSA"));
		logs.put("SIGN_CERT_SUBJECT", cert.getSubject());
		logs.put("SIGN_CERTIFICATE", SignHelper.SIGN_CERT);
		logs.put("STATUS", LoggerEnum.SUCCESS_CN);
		logs.put("ACCESSED_TIME", new Date());
		logs.put("FINISHED_TIME", new Date());
		logs.put("SESSION_ID", "");
		logs.put("SIGNED_DATA", SignHelper.SIGN_RESULT);
		logs.put("SIGNED_DATA_TYPE", "P7verify");
		logs.put("PLAIN_DATA", SignHelper.PLAIN);
		logs.put("PLAIN_TYPE", "0");
		return logs;
	}
	
	/**
	 * 准备p7验签业务日志数据
	 * @return logs
	 * @throws Exception
	 */
	private Map<String, Object> buildP1VerifyBusinessLog() throws Exception {
		X509Cert cert = new X509Cert(SignHelper.SIGN_CERT);
		Map<String, Object> logs = new LinkedHashMap<>();
		logs.put("CLIENT_IP", "127.0.0.1");
		logs.put("BUSINESS_TYPE", "verifyP1Sign");
		logs.put("DIGEST_ALGORITHM", "sha1");
		logs.put("DIGEST_DATA", null);
		logs.put("SIGN_ALGORITHM", ("SHA1WITHRSA"));
		logs.put("SIGN_CERT_SUBJECT", cert.getSubject());
		logs.put("SIGN_CERTIFICATE", SignHelper.SIGN_CERT);
		logs.put("STATUS", LoggerEnum.SUCCESS_CN);
		logs.put("ACCESSED_TIME", new Date());
		logs.put("FINISHED_TIME", new Date());
		logs.put("SESSION_ID", "");
		logs.put("SIGNED_DATA", SignHelper.SIGN_RESULT);
		logs.put("SIGNED_DATA_TYPE", "P1Verify");
		logs.put("PLAIN_DATA", SignHelper.PLAIN);
		logs.put("PLAIN_TYPE", "0");
		return logs;
	}
	
	/**
	 * 准备p1签名业务日志数据
	 * @return logs
	 * @throws PKIException 
	 */
	private Map<String, Object> buildP1SignBusinessLog() throws Exception {
		X509Cert cert = new X509Cert(SignHelper.SIGN_CERT);
		Map<String, Object> logs = new LinkedHashMap<>();
		logs.put("CLIENT_IP", "127.0.0.1");
		logs.put("BUSINESS_TYPE", "P1Sign");
		logs.put("DIGEST_ALGORITHM", "sha1");
		logs.put("DIGEST_DATA", null);
		logs.put("SIGN_ALGORITHM", ("SHA1WITHRSA"));
		logs.put("SIGN_CERT_SUBJECT", cert.getSubject());
		logs.put("SIGN_CERTIFICATE", SignHelper.SIGN_CERT);
		logs.put("STATUS", LoggerEnum.SUCCESS_CN);
		logs.put("ACCESSED_TIME", new Date());
		logs.put("FINISHED_TIME", new Date());
		logs.put("SIGNED_DATA", SignHelper.SIGN_ATTACH_RESULT);
		logs.put("SIGNED_DATA_TYPE", "P1Sign");
		logs.put("PLAIN_DATA", SignHelper.PLAIN);
		logs.put("PLAIN_TYPE", "0");
		return logs;
	}
	
	/**
	 * 准备信封业务日志数据
	 * @return logs
	 * @throws Exception
	 */
	private Map<String, Object> buildEncEnvelopBusinessLog() throws Exception {
		Map<String, Object> logs = new LinkedHashMap<>();
		logs.put("BUSINESS_TYPE", "encEnvelop");
		logs.put("CLIENT_IP", "127.0.0.1");
		logs.put("STATUS", LoggerEnum.SUCCESS_CN);
		logs.put("ACCESSED_TIME", new Date());
		logs.put("FINISHED_TIME", new Date());
		logs.put("SYMMETRIC_ALGORITHM", "des3");
		logs.put("ASYMMETRIC_ALGORITHM", "rsa");
		logs.put("ENVELOPENC_CERT_SUBJECT", "C=cn,O=jit,E=normal@jit.com.cn,CN=normal");
		logs.put("ENCRYPTION_CERTIFICATE", SignHelper.SIGN_CERT);
		logs.put("ENVELOP_DATA", SignHelper.ENVELOPEDATA);
		return logs;
	}
	
	/**
	 * 准备信封业务日志数据
	 * @return logs
	 * @throws Exception
	 */
	private Map<String, Object> buildDecEnvelopBusinessLog() throws Exception {
		Map<String, Object> logs = new LinkedHashMap<>();
		logs.put("BUSINESS_TYPE", "decEnvelop");
		logs.put("CLIENT_IP", "127.0.0.1");
		logs.put("STATUS", LoggerEnum.SUCCESS_CN);
		logs.put("ACCESSED_TIME", new Date());
		logs.put("FINISHED_TIME", new Date());
		logs.put("SYMMETRIC_ALGORITHM", "des3");
		logs.put("ASYMMETRIC_ALGORITHM", "rsa");
		logs.put("ENVELOPDEC_CERT_SUBJECT", "C=cn,O=jit,E=normal@jit.com.cn,CN=normal");
		logs.put("DECRYPTION_CERTIFICATE", SignHelper.SIGN_CERT);
		logs.put("ENVELOP_DATA", SignHelper.ENVELOPEDATA);
		return logs;
	}
	
	/**
	 * 准备错误日志数据
	 * @return errors
	 */
	private Map<String, Object> buildErrorLog() {
		Map<String, Object> errors = new LinkedHashMap<>();
		errors.put("CLIENT_IP", "127.0.0.1");
		errors.put("ERROR_CODE", "FF1C0901");
		errors.put("ERROR_DESC", "根据指定的证书标识或别名[111]没有找到对应的证书，请检查与服务器配置的证书标识或别名是否一致。, CREATE_TIME=20150108235428655, ID=875ed134f07b4cdeaac0ea6391eef22e");
		errors.put("ACCESSED_TIME", new Date());
		errors.put("FINISHED_TIME", new Date());
		errors.put("STATUS", "失败");
		return errors;
	}

}
