package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.ENVELOPEDATA;
import static cn.com.jit.platform.pki.SignHelper.ENVELOPEDATE_BASE64;
import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.PLAINBASE;
import static cn.com.jit.platform.pki.SignHelper.PRVKEY;
import static cn.com.jit.platform.pki.SignHelper.SIGN_CERT;
import static cn.com.jit.platform.pki.SignHelper.assertFailP7Envelope;
import static cn.com.jit.platform.pki.SignHelper.assertFailp7DecryptEnvelope;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessP7DecryptEnvelope;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessP7Envelope;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessP7EnvelopeBase64;

import org.junit.Test;

import cn.com.jit.assp.css.client.util.Base64;

public class PKIToolkitsP7EnvelopeTest extends BasePKIToolKitsTest {

	/**
	 * 打信封单元测试用例
	 */
	HandleResult	handleResult	= new HandleResult();

	@Test
	public void should_return_right_p7_envelope_without_base64() {

		// 测试执行
		pkiTool.p7Envelope(SIGN_CERT, PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 0, PLAIN, handleResult);
		// 测试结果
		//assertSuccessP7Envelope(handleResult);
		System.out.print(new String(Base64.encode(handleResult.resultData)));
	}

	@Test
	public void should_return_right_P7_envelope_with_base64() {
		// 测试执行
		pkiTool.p7Envelope(SIGN_CERT, PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 2, PLAINBASE, handleResult);
		// 测试结果
		assertSuccessP7EnvelopeBase64(handleResult);
	}

	@Test
	public void should_return_plain_is_null_p7_envelope_without_base64() {
		// 测试执行
		pkiTool.p7Envelope(SIGN_CERT, PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, null, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_public_key_cert_is_null_with_base64() {
		// 测试执行
		pkiTool.p7Envelope(null, PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 2, PLAINBASE, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_symmetricarithmetictype_is_null_without_base64() {
		// 测试执行
		pkiTool.p7Envelope(SIGN_CERT, null, 0, PLAIN, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_plain_is_empty_without_base64() {
		// 测试执行
		pkiTool.p7Envelope(SIGN_CERT, PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, "".getBytes(), handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_public_key_cert_is_empty_without_base64() {
		// 测试执行
		pkiTool.p7Envelope("".getBytes(), PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, PLAIN, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_type_is_empty_without_base64() {
		// 测试执行
		pkiTool.p7Envelope(SIGN_CERT, "", 0, PLAIN, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);

	}

	@Test
	public void should_return_flag_is_negtive_without_base64() {
		// 测试执行
		pkiTool.p7Envelope(SIGN_CERT, PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, -1, PLAIN, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_public_cert_is_special_character_without_base64() {
		// 测试执行
		pkiTool.p7Envelope("&^%$8".getBytes(), PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, PLAIN, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_type_is_special_character_without_base64() {
		// 测试执行
		pkiTool.p7Envelope(SIGN_CERT, "\\/;:", 0, PLAIN, handleResult);
		// 测试结果
		assertFailP7Envelope(handleResult);
	}

	@Test
	public void should_return_plain_is_special_character_without_base64() {
		// 测试执行
		pkiTool.p7Envelope(SIGN_CERT, PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, "[]^!~".getBytes(),
				handleResult);
		// 测试结果
		assertSuccessP7Envelope(handleResult);
	}

	/**
	 * p7解信封
	 */
	@Test
	public void should_right_without_base64_p7decrypt_envelope() {
		// 测试执行
		pkiTool.p7DecryptEnvelope(PRVKEY, 0, ENVELOPEDATA, handleResult);
		// 测试结果
		assertSuccessP7DecryptEnvelope(handleResult);
	}

	@Test
	public void should_return_right_with_base64_p7decrypt_envelope() {
		// 测试执行
		pkiTool.p7DecryptEnvelope(PRVKEY, 2, ENVELOPEDATE_BASE64, handleResult);
		// 测试结果
		assertSuccessP7DecryptEnvelope(handleResult);
	}

	@Test
	public void should_return_sign_pfx_is_null_without_base64() {
		// 测试执行
		pkiTool.p7DecryptEnvelope(null, 0, ENVELOPEDATA, handleResult);
		// 测试结果
		assertFailp7DecryptEnvelope(handleResult);
	}

	@Test
	public void should_return_envelopedate_is_null_without_base64() {
		// 测试执行
		pkiTool.p7DecryptEnvelope(PRVKEY, 0, null, handleResult);
		// 测试结果
		assertFailp7DecryptEnvelope(handleResult);
	}

	@Test
	public void should_return_sign_pfx_is_empty_without_base64() {
		// 测试执行
		pkiTool.p7DecryptEnvelope("".getBytes(), 0, ENVELOPEDATA, handleResult);
		// 测试结果
		assertFailp7DecryptEnvelope(handleResult);

	}

	@Test
	public void should_return_envelopedate_is_empty() {
		// 测试执行
		pkiTool.p7DecryptEnvelope(PRVKEY, 0, "".getBytes(), handleResult);
		// 测试结果
		assertFailp7DecryptEnvelope(handleResult);
	}

	@Test
	public void should_return_flag_is_negtive_decrypt_envelope_without_base64() {
		// 测试执行
		pkiTool.p7DecryptEnvelope(PRVKEY, -1, ENVELOPEDATA, handleResult);
		// 测试结果
		assertFailp7DecryptEnvelope(handleResult);
	}

	@Test
	public void should_return_sign_pfx_is_special_decrypt_envelope_without_base64() {
		// 测试执行
		pkiTool.p7DecryptEnvelope("<>".getBytes(), 0, ENVELOPEDATA, handleResult);
		// 测试结果
		assertFailp7DecryptEnvelope(handleResult);

	}

	@Test
	public void should_return_envelopedate_is_special_character_decrypt_envelope_without_base64() {
		// 测试执行
		pkiTool.p7DecryptEnvelope(PRVKEY, 0, "%^&*@!".getBytes(), handleResult);
		// 测试结果
		assertFailp7DecryptEnvelope(handleResult);
	}
}
