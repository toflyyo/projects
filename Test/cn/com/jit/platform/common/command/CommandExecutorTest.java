package cn.com.jit.platform.common.command;

import static cn.com.jit.platform.common.command.CommandExecutorTestHelper.createProcessCreatorMock;
import static cn.com.jit.platform.common.command.CommandExecutorTestHelper.destroy;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Test;

public class CommandExecutorTest {
	@After
	public void tearDown() throws Exception {
		destroy();
	}

	@Test(expected = IllegalArgumentException.class)
	public void should_throw_illegal_argument_exception_when_execute_empty_command() {
		CommandExecutor commandUtils = new CommandExecutor();
		commandUtils.execCommand("");
	}

	@Test(expected = IllegalArgumentException.class)
	public void should_throw_illegal_argument_exception_when_execute_null_command() {
		CommandExecutor commandUtils = new CommandExecutor();
		commandUtils.execCommand(null);
	}

	@Test
	public void should_return_true_when_execute_correct_command() throws InterruptedException {
		CommandExecutor commandUtils = new CommandExecutor(createProcessCreatorMock(0));
		assertTrue(commandUtils.execCommand("correct command"));
	}

	@Test(expected = CommandExecuteException.class)
	public void should_return_true_when_execute_error_command() throws InterruptedException {
		CommandExecutor commandUtils = new CommandExecutor(createProcessCreatorMock(100));
		commandUtils.execCommand("error command");
	}

}
