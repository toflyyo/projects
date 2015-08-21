package cn.com.jit.platform.mainprocess.childProcessManager;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

import cn.com.jit.cloud.common.message.IMessageListener;
import cn.com.jit.cloud.common.message.IMessager;
import cn.com.jit.platform.common.command.CommandExecutor;
import cn.com.jit.platform.mainprocess.bean.ChildProcessInfos;

public class ChildProcessManagerTest {

	private IMessager			messagerMock;
	private CommandExecutor		commandMock;
	private OSInfo				osinfoMock;
	private ChildProcessManager	childProcessManager;

	@Before
	public void setUp() {
		messagerMock = EasyMock.createNiceMock(IMessager.class);
		commandMock = EasyMock.createNiceMock(CommandExecutor.class);
		osinfoMock = EasyMock.createNiceMock(OSInfo.class);
		childProcessManager = new ChildProcessManager(messagerMock);
	}

	@Test
	public void should_start_childProcess_batch_success() {
		// 测试准备
		createMessagerMockData();
		createCommandMockData();
		createOsinfoMock(6);
		// 测试执行
		childProcessManager.promoterProcess();
		// 测试结果
		EasyMock.verify(messagerMock);

	}

	private void createCommandMockData() {
		EasyMock.expect(commandMock.execShellFile(EasyMock.anyString())).andReturn(true);
		EasyMock.replay(commandMock);
		childProcessManager.setCommandUtils(commandMock);
	}

	private void createMessagerMockData() {
		messagerMock.registListener(EasyMock.anyString(), (IMessageListener) EasyMock.anyObject());
		EasyMock.expectLastCall();
		EasyMock.replay(messagerMock);
	}
	
	private void createOsinfoMock(int memorySize){
		EasyMock.expect(osinfoMock.getMemory()).andReturn(memorySize);
		EasyMock.replay(osinfoMock);
		ChildProcessInfos.setOsInfo(osinfoMock);
	}
}
