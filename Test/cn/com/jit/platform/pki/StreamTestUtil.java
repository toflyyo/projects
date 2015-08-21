package cn.com.jit.platform.pki;


import java.util.Arrays;

public class StreamTestUtil  extends BasePKIToolKitsTest {
	private HandleResult out = new HandleResult();
	
	public HandleResult p7SignStream(byte[] originalData,int flag,byte[] privateKey,byte[] publicKey,String digestArithmeticType ){
		pkiTool.p7SignInit(privateKey, publicKey, digestArithmeticType, originalData.length, flag, out);
		if(out.errorCode!=0){
			throw new RuntimeException(new String(out.errorDescription));
		}
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		byte[] resultBytes = new byte[0];
		while (true) {
			int end = index + step;
			if(end > originalData.length){
				end = originalData.length;
				blocks = new byte[originalData.length-index];
			}
			blocks = Arrays.copyOfRange(originalData, index, end);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7SignUpdate(out.handle, publicKey, blocks, resultTmp);
			resultBytes = mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=originalData.length){
				break;
			}
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7SignFinal(out.handle, publicKey,null,	resultTmp);
		resultTmp.setResultData(mergeBytes(resultBytes, resultTmp.getResultData()));
		return resultTmp;
	}
	
	public static byte[] mergeBytes(byte[] one, byte[] two) {
		if (two == null) {
			return one;
		}

		byte[] result = new byte[one.length + two.length];
		System.arraycopy(one, 0, result, 0, one.length);
		System.arraycopy(two, 0, result, one.length, two.length);
		return result;
	}
	
	public HandleResult p7AttachVerifyStream(byte[] signData,int flag,byte[] privateKey,byte[] publicKey,String digestArithmeticType){
		out = new HandleResult();
		pkiTool.p7attachVerifyInit(publicKey, flag, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		byte[] resultBytes = new byte[0];
		while (true) {
			int endIndex = index + step;
			if(endIndex > signData.length){
				endIndex=signData.length;
				blocks = new byte[signData.length-(endIndex-step)];
			}
			blocks = Arrays.copyOfRange(signData, index, endIndex);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7attachVerifyUpdate(out.handle, blocks, resultTmp);
			resultBytes = mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=signData.length)
				break;
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7attachVerifyFinal(out.handle, resultTmp);
		resultTmp.setResultData(mergeBytes(resultBytes, resultTmp.getResultData()));
		return resultTmp;
	}
	public HandleResult p7DetachVerifyStream(byte[] signData,byte[] originalData,int flag,byte[] privateKey,byte[] publicKey,String digestArithmeticType){
		out = new HandleResult();
		pkiTool.p7detachVerifyInit(signData, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		byte[] resultBytes = new byte[0];
		while (true) {
			int endIndex = index + step;
			if(endIndex > originalData.length){
				endIndex=originalData.length;
				blocks = new byte[originalData.length-(endIndex-step)];
			}
			blocks = Arrays.copyOfRange(originalData, index, endIndex);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7detachVerifyUpdate(out.handle, blocks, resultTmp);
			resultBytes = mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=originalData.length)
				break;
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7detachVerifyFinal(out.handle, resultTmp);
		resultTmp.setResultData(mergeBytes(resultBytes, resultTmp.getResultData()));
		return resultTmp;
	}
	
}
