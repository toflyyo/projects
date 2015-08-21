package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.*;

import org.junit.Test;

import cn.com.jit.assp.css.client.util.Base64;

public class PKIToolkitsSymmetricKeyTest extends BasePKIToolKitsTest {
	HandleResult	handleResult	= new HandleResult();

	@Test
	public void should_return_symmetric_key_encryption_without_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV, 0, PLAIN,
				handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_sm2_encryption_without_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_SM4, SYMMETRICKEY, IV, 0, PLAIN, handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_rc4_without_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, SYMMETRICKEY, IV, 0, PLAIN, handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_ede3_cbc_without_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, SYMMETRICKEY, IV, 0, PLAIN,
				handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_des_ecb_without_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, SYMMETRICKEY, IV, 0, PLAIN,
				handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_aes_cbc_without_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, SYMMETRICKEY, IV, 0, PLAIN,
				handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_aes_ecb_without_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, SYMMETRICKEY, IV, 0, PLAIN,
				handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_des_ede3_without_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, SYMMETRICKEY, IV, 0, PLAIN,
				handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_key_encryption_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV, 2, PLAINBASE,
				handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_rc4_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, SYMMETRICKEY, IV, 2, PLAINBASE,
				handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_sm2_encryption_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_SM4, SYMMETRICKEY, IV, 2, PLAINBASE,
				handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_ede3_cbc_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, SYMMETRICKEY, IV, 2, PLAINBASE,
				handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_des_ecb_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, SYMMETRICKEY, IV, 2, PLAINBASE,
				handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_aes_cbc_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, SYMMETRICKEY, IV, 2, PLAINBASE,
				handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_aes_ecb_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, SYMMETRICKEY, IV, 2, PLAINBASE,
				handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_des_ede3_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, SYMMETRICKEY, IV, 2, PLAINBASE,
				handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(null, SYMMETRICKEY, IV, 2, PLAINBASE, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_key_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, null, IV, 2, PLAINBASE, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_iv_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, SYMMETRICKEY, null, 2, PLAINBASE,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_plain_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, SYMMETRICKEY, IV, 2, null,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_plain_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, SYMMETRICKEY, IV, 2, "".getBytes(),
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_iv_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, SYMMETRICKEY, "".getBytes(), 2,
				PLAINBASE, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetrickey_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, "".getBytes(), IV, 2, PLAINBASE,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetricar_type_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption("", SYMMETRICKEY, IV, 2, PLAINBASE, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetricarithmetic_type_is_special_character_with_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption("*&^%(", SYMMETRICKEY, IV, 2, PLAINBASE, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetrickey_is_character_without_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, "<>//\\".getBytes(), IV, 0, PLAIN,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_iv_is_special_character_without_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, SYMMETRICKEY,
				"{}[]@——%￥#".getBytes(), 0, PLAIN, handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_plain_is_special_character_without_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, SYMMETRICKEY, IV, 0,
				",.:\"".getBytes(), handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_flag_is_negtive_without_base64() {
		// 测试执行
		pkiTool.symmetricalEncryption(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV, -1, PLAIN,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	/**
	 * 对称解密
	 */
	@Test
	public void should_return_symmetric_type_is_des_cbc_decryption_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, 0, SYMMETRICKEY, IV, handleResult);

		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_rc4_decryption_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_RC4_RESULT, PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 0,
				SYMMETRICKEY, IV, handleResult);

		// 测试结果
		assertSuccessSymmetricKey(handleResult);

	}

	@Test
	public void should_return_symmetric_type_is_des_ede3_cbc_decryption_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, SYMMETRICKEY, IV, handleResult);

		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_des_ecb_decryption_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_ECB_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, 0, SYMMETRICKEY, IV, handleResult);

		// 测试结果
		assertSuccessSymmetricKey(handleResult);

	}

	@Test
	public void should_return_symmetric_type_is_des_ede3_decryption_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, 0, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_aes_128_ecb_decryption_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_ECB_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, 0, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_aes_128_cbc_decryption_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, 0, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_des_cbc_decryption_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, 2, SYMMETRICKEY, IV, handleResult);

		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_rc4_decryption_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_RC4_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 2, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_symmetric_type_is_des_ede3_cbc_decryption_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 2, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);

	}

	@Test
	public void should_return_symmetric_type_is_des_ecb_decryption_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_ECB_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, 2, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);

	}

	@Test
	public void should_return_symmetric_type_is_des_ede3_decryption_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, 2, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);

	}

	@Test
	public void should_return_symmetric_type_is_aes_128_ecb_decryption_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_ECB_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, 2, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);

	}

	@Test
	public void should_return_symmetric_type_is_aes_128_cbc_decryption_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, 2, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);

	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_CBC_RESULT, null, 0, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_cbc_and_encryption_result_is_null() {
		// 测试执行
		pkiTool.symmetricalDecryption(null, PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, 0, SYMMETRICKEY, IV,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_rc4_and_encryption_result_is_null() {
		// 测试执行
		pkiTool.symmetricalDecryption(null, PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 0, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_and_encryption_result_is_null() {
		// 测试执行
		pkiTool.symmetricalDecryption(null, PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, 0, SYMMETRICKEY, IV,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_cbc_and_encryption_result_is_null() {
		// 测试执行
		pkiTool.symmetricalDecryption(null, PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, SYMMETRICKEY, IV,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ecb_and_encryption_result_is_null() {
		// 测试执行
		pkiTool.symmetricalDecryption(null, PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, 0, SYMMETRICKEY, IV,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_ecb_and_encryption_result_is_null() {
		// 测试执行
		pkiTool.symmetricalDecryption(null, PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, 0, SYMMETRICKEY, IV,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_cbc_and_encryption_result_is_null() {
		// 测试执行
		pkiTool.symmetricalDecryption(null, PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, 0, SYMMETRICKEY, IV,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_cbc_and_encryption_result_is_empty() {
		// 测试执行
		pkiTool.symmetricalDecryption("".getBytes(), PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, 0, SYMMETRICKEY, IV,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_rc4_and_encryption_result_is_empty() {
		// 测试执行
		pkiTool.symmetricalDecryption("".getBytes(), PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 0, SYMMETRICKEY, IV,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_and_encryption_result_is_empty() {
		// 测试执行
		pkiTool.symmetricalDecryption("".getBytes(), PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, 0, SYMMETRICKEY, IV,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_cbc_and_encryption_result_is_empty() {
		// 测试执行
		pkiTool.symmetricalDecryption("".getBytes(), PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, SYMMETRICKEY,
				IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ecb_and_encryption_result_is_empty() {
		// 测试执行
		pkiTool.symmetricalDecryption("".getBytes(), PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, 0, SYMMETRICKEY, IV,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_ecb_and_encryption_result_is_empty() {
		// 测试执行
		pkiTool.symmetricalDecryption("".getBytes(), PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, 0, SYMMETRICKEY,
				IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_cbc_and_encryption_result_is_empty() {
		// 测试执行
		pkiTool.symmetricalDecryption("".getBytes(), PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, 0, SYMMETRICKEY,
				IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_cbc_and_iv_is_empty_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, 0, SYMMETRICKEY, "".getBytes(), handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_rc4_and_iv_is_empty_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_RC4_RESULT, PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 0,
				SYMMETRICKEY, "".getBytes(), handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_and_iv_is_empty_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, 0, SYMMETRICKEY, "".getBytes(), handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_cbc_and_iv_is_empty_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, SYMMETRICKEY, "".getBytes(), handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ecb_and_iv_is_empty_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_ECB_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, 0, SYMMETRICKEY, "".getBytes(), handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_ecb_and_iv_is_empty_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_ECB_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, 0, SYMMETRICKEY, "".getBytes(), handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_cbc_and_iv_is_empty_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, 0, SYMMETRICKEY, "".getBytes(), handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_cbc_and_iv_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, 2, SYMMETRICKEY, "".getBytes(), handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_rc4_and_iv_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_RC4_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 2, SYMMETRICKEY, "".getBytes(), handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_and_iv_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, 2, SYMMETRICKEY, "".getBytes(), handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_cbc_and_iv_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 2, SYMMETRICKEY, "".getBytes(), handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ecb_and_iv_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_ECB_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, 2, SYMMETRICKEY, "".getBytes(), handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_ecb_and_iv_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_ECB_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, 2, SYMMETRICKEY, "".getBytes(), handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_cbc_and_iv_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, 2, SYMMETRICKEY, "".getBytes(), handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_cbc_and_iv_is_null_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, 0, SYMMETRICKEY, null, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_rc4_and_iv_is_null_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_RC4_RESULT, PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 0,
				SYMMETRICKEY, null, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_and_iv_is_null_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, 0, SYMMETRICKEY, null, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_cbc_and_iv_is_null_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, SYMMETRICKEY, null, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ecb_and_iv_is_null_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_ECB_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, 0, SYMMETRICKEY, null, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_ecb_and_iv_is_null_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_ECB_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, 0, SYMMETRICKEY, null, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_cbc_and_iv_is_null_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, 0, SYMMETRICKEY, null, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_cbc_and_iv_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, 2, SYMMETRICKEY, null, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_rc4_and_iv_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_RC4_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 2, SYMMETRICKEY, null, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_and_iv_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, 2, SYMMETRICKEY, null, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_cbc_and_iv_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 2, SYMMETRICKEY, null, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ecb_and_iv_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_ECB_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, 2, SYMMETRICKEY, null, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_ecb_and_iv_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_ECB_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, 2, SYMMETRICKEY, null, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_cbc_and_iv_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, 2, SYMMETRICKEY, null, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_cbc_and_symmetricKey_is_null_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, 0, null, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_rc4_and_symmetricKey_is_null_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_RC4_RESULT, PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 0,
				null, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_and_symmetricKey_is_null_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, 0, null, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_cbc_and_symmetricKey_is_null_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, null, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ecb_and_symmetricKey_is_null_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_ECB_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, 0, null, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_ecb_and_symmetricKey_is_null_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_ECB_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, 0, null, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_cbc_and_symmetricKey_is_null_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, 0, null, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_cbc_and_symmetricKey_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, 2, null, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_rc4_and_symmetricKey_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_RC4_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 2, null, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_and_symmetricKey_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, 2, null, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_cbc_and_symmetricKey_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 2, null, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ecb_and_symmetricKey_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_ECB_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, 2, null, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_ecb_and_symmetricKey_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_ECB_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, 2, null, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_cbc_and_symmetricKey_is_null_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, 2, null, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_cbc_and_symmetricKey_is_empty_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, 0, "".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_rc4_and_symmetricKey_is_empty_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_RC4_RESULT, PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 0,
				"".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_and_symmetricKey_is_empty_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, 0, "".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_cbc_and_symmetricKey_is_empty_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, "".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ecb_and_symmetricKey_is_empty_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_ECB_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, 0, "".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_ecb_and_symmetricKey_is_empty_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_ECB_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, 0, "".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_cbc_and_symmetricKey_is_empty_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, 0, "".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_cbc_and_symmetricKey_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, 2, "".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_rc4_and_symmetricKey_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_RC4_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 2, "".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_and_symmetricKey_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, 2, "".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ede3_cbc_and_symmetricKey_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_EDE3_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 2, "".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_des_ecb_and_iv_symmetricKey_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_DES_ECB_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, 2, "".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_ecb_and_symmetricKey_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_ECB_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, 2, "".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetric_type_is_aes_128_cbc_and_symmetricKey_is_empty_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, 2, "".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_iv_is_negtive_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_CBC_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, -1, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_iv_is_negtive_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_AES_128_CBC_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, -1, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetricarithmetic_type_is_special_character_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_RC4_BASE64_RESULT, "*&^%(", 2, SYMMETRICKEY, IV,
				handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetricarithmetic_type_is_special_character_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_RC4_RESULT, "*&^%(", 0, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetrickey_is_character_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_RC4_RESULT, PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 0,
				"<>//\\".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_symmetrickey_is_character_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_RC4_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 2, "<>//\\".getBytes(), IV, handleResult);
		// 测试结果
		assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_iv_is_special_character_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_RC4_RESULT, PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 0,
				SYMMETRICKEY, "{}[]@——%￥#".getBytes(), handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_error_code_when_decryption_encryptionResult_is_special_character_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(Base64.encode(",.:\"".getBytes()), PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, 2,
				SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_success_sm2_decryption_when_symmetricarithmetictype_is_sm4_ecb_and_with_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_SM4_ECB_RESULT, PKIToolkits.SYMMETRICARITHMETICTYPE_SM4,
				2, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertSuccess(handleResult);
	}

	@Test
	public void should_return_success_sm2_decryption_when_symmetricarithmetictype_is_sm4_ecb_and_without_base64() {
		// 测试执行
		pkiTool.symmetricalDecryption(SYMMETRICARITHMETICTYPE_SM4_ECB_BASE64_RESULT,
				PKIToolkits.SYMMETRICARITHMETICTYPE_SM4, 0, SYMMETRICKEY, IV, handleResult);
		// 测试结果
		assertSuccess(handleResult);
	}
}
