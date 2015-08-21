package cn.com.jit.platform.common.command;

import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class CommandExecutorTestHelper {
	private static InputStream	expectErrorStream	= new ByteArrayInputStream("error message".getBytes());
	private static InputStream	expectSucessStream	= new ByteArrayInputStream("".getBytes());

	public static void destroy() throws IOException {
		expectErrorStream.close();
		expectSucessStream.close();
	}

	public static Process createProcessMock(int exitValue) throws InterruptedException {
		Process process = createNiceMock(Process.class);
		expect(process.waitFor()).andReturn(exitValue);

		InputStream errorStream = expectSucessStream;
		// 退出码不是0的时候，代表有异常
		if (exitValue != 0) {
			errorStream = expectErrorStream;
		}
		expect(process.getErrorStream()).andReturn(errorStream);
		replay(process);

		return process;
	}

	public static ProcessCreator createProcessCreatorMock(int exitValue) throws InterruptedException {
		Process processMock = createProcessMock(exitValue);
		ProcessCreator processCreatorMock = createMock(ProcessCreator.class);
		expect(processCreatorMock.execCommand(anyString())).andReturn(processMock);
		replay(processCreatorMock);
		return processCreatorMock;
	}
}
