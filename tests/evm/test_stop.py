import pytest

from itertools import chain
from common import CallContext, rand_fq
from zkevm_specs.evm_circuit import (
    ExecutionState,
    StepState,
    verify_steps,
    Tables,
    CallContextFieldTag,
    Block,
    Bytecode,
    CallContextFieldTag,
    ExecutionState,
    RWDictionary,
    StepState,
    Tables,
    Transaction,
    verify_steps,
)
from zkevm_specs.util import (
    DEPOSIT_TX_TYPE,
    RLC
)

BYTECODE_END_WITHOUT_STOP = Bytecode().push(0, n_bytes=1)
BYTECODE_END_WITH_STOP = Bytecode().push(0, n_bytes=1).stop()

TESTING_DATA_IS_ROOT = (
    (Transaction(), False, BYTECODE_END_WITHOUT_STOP, True),
    (Transaction(), False, BYTECODE_END_WITH_STOP, True),

    (Transaction(type_=DEPOSIT_TX_TYPE), False, BYTECODE_END_WITHOUT_STOP, True),
    (Transaction(type_=DEPOSIT_TX_TYPE), False, BYTECODE_END_WITH_STOP, True),

    (Transaction(), True, BYTECODE_END_WITHOUT_STOP, False),
    (Transaction(), True, BYTECODE_END_WITH_STOP, False),
    (Transaction(type_=DEPOSIT_TX_TYPE), True, BYTECODE_END_WITHOUT_STOP, False),
    (Transaction(type_=DEPOSIT_TX_TYPE), True, BYTECODE_END_WITH_STOP, False),
)


@pytest.mark.parametrize("tx, wrong_step, bytecode, success", TESTING_DATA_IS_ROOT)
def test_stop_is_root(
    tx: Transaction,
    wrong_step: bool,
    bytecode: Bytecode,
    success: bool
):
    randomness = rand_fq()

    block = Block()

    bytecode_hash = RLC(bytecode.hash(), randomness)

    rw_dictionary = (
        # fmt: off
        RWDictionary(24)
            .call_context_read(1, CallContextFieldTag.IsSuccess, 1)
            .call_context_read(1, CallContextFieldTag.TxId, tx.id)
            .call_context_read(1, CallContextFieldTag.IsPersistent, 1)
        # fmt: on
    )

    tables = Tables(
        block_table=set(block.table_assignments(randomness)),
        tx_table=set(
            chain(
                tx.table_assignments(randomness),
                Transaction(id=tx.id + 1).table_assignments(randomness),
            )
        ),
        bytecode_table=set(bytecode.table_assignments(randomness)),
        rw_table=set(rw_dictionary.rws),
    )

    if wrong_step:
        next_step = StepState(
            execution_state=ExecutionState.EndTx,
            rw_counter=27,
            call_id=1,
        )
    elif tx.type_ == DEPOSIT_TX_TYPE:
        next_step = StepState(
            execution_state=ExecutionState.EndDepositTx,
            rw_counter=27,
            call_id=1,
        )
    else:
        next_step = StepState(
            execution_state=ExecutionState.BaseFeeHook,
            rw_counter=27,
            call_id=1,
        )

    verify_steps(
        randomness=randomness,
        tables=tables,
        steps=[
            StepState(
                execution_state=ExecutionState.STOP,
                rw_counter=24,
                call_id=1,
                is_root=True,
                is_create=False,
                code_hash=bytecode_hash,
                program_counter=2,
                stack_pointer=1023,
                gas_left=0,
                reversible_write_counter=2,
            ),
            next_step
        ],
        success=success
    )


TESTING_DATA_NOT_ROOT = (
    (CallContext(), BYTECODE_END_WITHOUT_STOP),
    (CallContext(), BYTECODE_END_WITH_STOP),
)


@pytest.mark.parametrize("caller_ctx, callee_bytecode", TESTING_DATA_NOT_ROOT)
def test_stop_not_root(caller_ctx: CallContext, callee_bytecode: Bytecode):
    randomness = rand_fq()

    caller_bytecode = Bytecode().call(0, 0xFF, 0, 0, 0, 0, 0).stop()
    caller_bytecode_hash = RLC(caller_bytecode.hash(), randomness)
    callee_bytecode_hash = RLC(callee_bytecode.hash(), randomness)
    callee_gas_left = 400
    callee_reversible_write_counter = 2

    tables = Tables(
        block_table=set(Block().table_assignments(randomness)),
        tx_table=set(),
        bytecode_table=set(
            chain(
                caller_bytecode.table_assignments(randomness),
                callee_bytecode.table_assignments(randomness),
            )
        ),
        rw_table=set(
            # fmt: off
            RWDictionary(69)
            .call_context_read(24, CallContextFieldTag.IsSuccess, 1)
            .call_context_read(24, CallContextFieldTag.CallerId, 1)
            .call_context_read(1, CallContextFieldTag.IsRoot, caller_ctx.is_root)
            .call_context_read(1, CallContextFieldTag.IsCreate, caller_ctx.is_create)
            .call_context_read(1, CallContextFieldTag.CodeHash, caller_bytecode_hash)
            .call_context_read(1, CallContextFieldTag.ProgramCounter, caller_ctx.program_counter)
            .call_context_read(1, CallContextFieldTag.StackPointer, caller_ctx.stack_pointer)
            .call_context_read(1, CallContextFieldTag.GasLeft, caller_ctx.gas_left)
            .call_context_read(1, CallContextFieldTag.MemorySize, caller_ctx.memory_word_size)
            .call_context_read(1, CallContextFieldTag.ReversibleWriteCounter, caller_ctx.reversible_write_counter)
            .call_context_write(1, CallContextFieldTag.LastCalleeId, 24)
            .call_context_write(1, CallContextFieldTag.LastCalleeReturnDataOffset, 0)
            .call_context_write(1, CallContextFieldTag.LastCalleeReturnDataLength, 0)
            .rws
            # fmt: on
        ),
    )

    verify_steps(
        randomness=randomness,
        tables=tables,
        steps=[
            StepState(
                execution_state=ExecutionState.STOP,
                rw_counter=69,
                call_id=24,
                is_root=False,
                is_create=False,
                code_hash=callee_bytecode_hash,
                program_counter=2,
                stack_pointer=1023,
                gas_left=callee_gas_left,
                reversible_write_counter=callee_reversible_write_counter,
            ),
            StepState(
                execution_state=ExecutionState.STOP,
                rw_counter=82,
                call_id=1,
                is_root=caller_ctx.is_root,
                is_create=caller_ctx.is_create,
                code_hash=caller_bytecode_hash,
                program_counter=caller_ctx.program_counter,
                stack_pointer=caller_ctx.stack_pointer,
                gas_left=caller_ctx.gas_left + callee_gas_left,
                memory_word_size=caller_ctx.memory_word_size,
                reversible_write_counter=caller_ctx.reversible_write_counter
                + callee_reversible_write_counter,
            ),
        ],
    )
