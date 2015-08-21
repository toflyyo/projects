package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.IV;
import static cn.com.jit.platform.pki.SignHelper.SYMMETRICARITHMETICTYPE_DES_CBC_RESULT;
import static cn.com.jit.platform.pki.SignHelper.SYMMETRICKEY;

import org.junit.Test;

public class PKIToolkitsSymmetricDecryptStreamParamsTest extends BasePKIToolKitsTest {
	HandleResult	handleResult	= new HandleResult();

	@Test
	public void should_return_fail_when_symmetricalDecryptionInit_with_empty_symmetricArithmetic() {
		pkiTool.symmetricalDecryptionInit("", SYMMETRICKEY, IV, SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length,
				handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalDecryptionInit_with_null_symmetricArithmetic() {
		pkiTool.symmetricalDecryptionInit(null, SYMMETRICKEY, IV, SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length,
				handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalDecryptionInit_with_invalid_symmetricArithmetic() {
		pkiTool.symmetricalDecryptionInit("*[]", SYMMETRICKEY, IV, SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length,
				handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalDecryptionInit_with_empty_symmetricKey() {
		pkiTool.symmetricalDecryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, new byte[0], IV,
				SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalDecryptionInit_with_null_symmetricKey() {
		pkiTool.symmetricalDecryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, null, IV,
				SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalDecryptionInit_with_invalid_symmetricKey() {
		pkiTool.symmetricalDecryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SignHelper.ZERO, IV,
				SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalDecryptionInit_with_empty_iv() {
		pkiTool.symmetricalDecryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, new byte[0],
				SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalDecryptionInit_with_null_iv() {
		pkiTool.symmetricalDecryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, null,
				SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalDecryptionInit_with_invalid_iv() {
		pkiTool.symmetricalDecryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, SignHelper.ZERO,
				SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalDecryptionInit_with_invalid_encryptDataLength() {
		pkiTool.symmetricalDecryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV, -1,
				handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_success_when_symmetricalDecryptionInit() {
		pkiTool.symmetricalDecryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV,
				SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length, handleResult);
		SignHelper.assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalDecryptionUpdate_with_invalid_handle() {
		pkiTool.symmetricalDecryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV,
				SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length, handleResult);
		pkiTool.symmetricalDecryptionUpdate(-1, SYMMETRICARITHMETICTYPE_DES_CBC_RESULT, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalDecryptionUpdate_with_empty_encryptData() {
		pkiTool.symmetricalDecryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV,
				SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length, handleResult);
		pkiTool.symmetricalDecryptionUpdate(handleResult.handle, new byte[0], handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalDecryptionUpdate_with_null_encryptData() {
		pkiTool.symmetricalDecryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV,
				SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length, handleResult);
		pkiTool.symmetricalDecryptionUpdate(handleResult.handle, null, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_success_when_symmetricalDecryptionUpdate() {
		pkiTool.symmetricalDecryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV,
				SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length, handleResult);
		pkiTool.symmetricalDecryptionUpdate(handleResult.handle, SYMMETRICARITHMETICTYPE_DES_CBC_RESULT, handleResult);
		SignHelper.assertSuccessSymmetricKey(handleResult);
	}

	@Test
	public void should_return_fail_when_symmetricalDecryptionFinal_with_invalid_handle() {
		pkiTool.symmetricalDecryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV,
				SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length, handleResult);
		pkiTool.symmetricalDecryptionUpdate(handleResult.handle, SYMMETRICARITHMETICTYPE_DES_CBC_RESULT, handleResult);
		pkiTool.symmetricalDecryptionFinal(-1, handleResult);
		SignHelper.assertFailSymmetricKey(handleResult);
	}

	@Test
	public void should_return_success_when_symmetricalDecryptionFinal() {
		pkiTool.symmetricalDecryptionInit(PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV,
				SYMMETRICARITHMETICTYPE_DES_CBC_RESULT.length, handleResult);
		long handle = handleResult.handle;
		pkiTool.symmetricalDecryptionUpdate(handle, SYMMETRICARITHMETICTYPE_DES_CBC_RESULT, handleResult);
		pkiTool.symmetricalDecryptionFinal(handle, handleResult);
		SignHelper.assertSuccessSymmetricKey(handleResult);
	}
}
