package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.IV;
import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.SYMMETRICKEY;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class PKIToolkitsSymmetricEncryptStreamSuccessTest extends BasePKIToolKitsTest {
	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = { { PKIToolkits.SYMMETRICARITHMETICTYPE_DES_CBC, SYMMETRICKEY, IV, PLAIN },
				{ PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, SYMMETRICKEY, IV, PLAIN },
				{ PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3, SYMMETRICKEY, IV, PLAIN },
				{ PKIToolkits.SYMMETRICARITHMETICTYPE_DES_ECB, SYMMETRICKEY, IV, PLAIN },
				{ PKIToolkits.SYMMETRICARITHMETICTYPE_SM4, SYMMETRICKEY, IV, PLAIN },
				{ PKIToolkits.SYMMETRICARITHMETICTYPE_RC4, SYMMETRICKEY, IV, PLAIN },
				{ PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_CBC, SYMMETRICKEY, IV, PLAIN },
				{ PKIToolkits.SYMMETRICARITHMETICTYPE_AES_128_ECB, SYMMETRICKEY, IV, PLAIN }, };
		return Arrays.asList(objects);
	}

	private String	symmetricArithmetic;
	private byte[]	symmetricKey;
	private byte[]	iv;
	private byte[]	plain;
	private ByteBuf	encryptResult;

	public PKIToolkitsSymmetricEncryptStreamSuccessTest(String symmetricArithmetic, byte[] symmetricKey, byte[] iv,
			byte[] plain) {
		this.symmetricArithmetic = symmetricArithmetic;
		this.symmetricKey = symmetricKey;
		this.iv = iv;
		this.plain = plain;
	}

	@Test
	public void testSymmetricalEncryption() {
		HandleResult encryptionResult = new HandleResult();
		pkiTool.symmetricalEncryptionInit(symmetricArithmetic, symmetricKey, iv, plain.length, encryptionResult);
		long handle = encryptionResult.handle;

		pkiTool.symmetricalEncryptionUpdate(handle, plain, encryptionResult);
		encryptResult = Unpooled.buffer((int) encryptionResult.dataLength);
		update(encryptionResult);

		pkiTool.symmetricalEncryptionFinal(handle, encryptionResult);
		update(encryptionResult);

		// 对加密结果进行解密
		HandleResult decryptionResult = new HandleResult();
		pkiTool.symmetricalDecryptionInit(symmetricArithmetic, symmetricKey, iv, encryptResult.capacity(),
				decryptionResult);
		handle = decryptionResult.handle;
		for (int i = 0; i < encryptResult.capacity(); i++) {
			byte o = encryptResult.getByte(i);
			pkiTool.symmetricalDecryptionUpdate(handle, new byte[] { o }, decryptionResult);
		}
		pkiTool.symmetricalDecryptionFinal(handle, decryptionResult);

		SignHelper.assertSuccessSymmetricKey(decryptionResult);
	}

	private void update(HandleResult result) {
		if (result.resultData != null) {
			encryptResult.writeBytes(result.resultData);
		}
	}
}
