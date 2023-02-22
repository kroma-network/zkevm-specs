import pytest

from zkevm_specs.evm import (
    ExecutionState,
    StepState,
    verify_steps,
    Tables,
    CallContextFieldTag,
    TxReceiptFieldTag,
    Block,
    Transaction,
    RWDictionary,
    L1BlockFieldTag, 
)
from zkevm_specs.util import rand_fq, RLC, DEPOSIT_TX_TYPE, EMPTY_CODE_HASH

CALLEE_ADDRESS = 0xFF
L1_BASE_FEE = 22492375312
L1_FEE_OVERHEAD = 2100
L1_FEE_SCALAR = 1000000

TESTING_DATA = (
    # System deposit tx
    (
        Transaction.system_deposit(),
        0,
        False,
        0,
        True,
        (L1_BASE_FEE, L1_FEE_OVERHEAD, L1_FEE_SCALAR),
    ),
    # Not a deposit transaction
    (
        Transaction(
            id=2, caller_address=0xFE, callee_address=CALLEE_ADDRESS, gas=27000, gas_price=int(2e9),
        ),
        994,
        False,
        0,
        False,
        (),
    ),
    # Tx with non-capped refund
    (
        Transaction(
            id=3, caller_address=0xFE, callee_address=CALLEE_ADDRESS, gas=27000, gas_price=int(2e9),
            type_=DEPOSIT_TX_TYPE
        ),
        994,
        False,
        0,
        True,
        (),
    ),
    # Tx with capped refund
    (
        Transaction(
            id=4, caller_address=0xFE, callee_address=CALLEE_ADDRESS, gas=65000, gas_price=int(2e9),
            type_=DEPOSIT_TX_TYPE
        ),
        3952,
        False,
        100,
        True,
        (),
    ),
    # Last tx
    (
        Transaction(
            id=5, caller_address=0xFE, callee_address=CALLEE_ADDRESS, gas=21000, gas_price=int(2e9),
            type_=DEPOSIT_TX_TYPE
        ),
        0,  # gas_left
        True,  # is_last_tx
        20000,  # current_cumulative_gas_used
        True,  # success
        (),
    ),
)


@pytest.mark.parametrize(
    "tx, gas_left, is_last_tx, current_cumulative_gas_used, success, l1_fee_data", TESTING_DATA
)
def test_end_deposit_tx(
    tx: Transaction,
    gas_left: int,
    is_last_tx: bool,
    current_cumulative_gas_used: int,
    success: bool,
    l1_fee_data: tuple
):
    randomness = rand_fq()
    block = Block()

    # check it is first tx
    is_first_tx = tx.id == 1

    rw_dictionary = (
        # fmt: off
        RWDictionary(14)
            .call_context_read(1, CallContextFieldTag.TxId, tx.id)
            .call_context_read(1, CallContextFieldTag.IsPersistent, 1)
            .tx_receipt_write(tx.id, TxReceiptFieldTag.PostStateOrStatus, 1)
            .tx_receipt_write(tx.id, TxReceiptFieldTag.LogLength, 0)
        # fmt: on
    )

    if is_first_tx:
        assert current_cumulative_gas_used == 0
        gas_used = 0
    else:
        gas_used = tx.gas
        rw_dictionary.tx_receipt_read(
            tx.id - 1, TxReceiptFieldTag.CumulativeGasUsed, current_cumulative_gas_used
        )
        
    rw_dictionary.tx_receipt_write(
        tx.id,
        TxReceiptFieldTag.CumulativeGasUsed,
        gas_used + current_cumulative_gas_used,
    )
    
    if is_first_tx:
        l1_base_fee, l1_fee_overhead, l1_fee_scalar = l1_fee_data
        rw_dictionary.l1_block_write(L1BlockFieldTag.L1BaseFee, l1_base_fee)
        rw_dictionary.l1_block_write(L1BlockFieldTag.L1FeeOverhead, l1_fee_overhead)
        rw_dictionary.l1_block_write(L1BlockFieldTag.L1FeeScalar, l1_fee_scalar)
    # rw count so far : 19 + (1-is_first_tx) + 3*is_first_tx = 20 + 2*is_first_tx

    if not is_last_tx:
        rw_dictionary.call_context_read(20 + 2*is_first_tx + 1, CallContextFieldTag.TxId, tx.id + 1)
        next_step = StepState(
            execution_state=ExecutionState.BeginTx ,
            rw_counter=20 + 2*is_first_tx + 1,
            call_id=0,
        )
    else:
        next_step = StepState(
            execution_state=ExecutionState.EndBlock ,
            rw_counter=20 + 2*is_first_tx,
            call_id=1,
        )

    tables = Tables(
        block_table=set(block.table_assignments(randomness)),
        tx_table=set(tx.table_assignments(randomness)),
        bytecode_table=set(),
        rw_table=set(rw_dictionary.rws),
    )

    verify_steps(
        randomness=randomness,
        tables=tables,
        steps=[
            StepState(
                execution_state=ExecutionState.EndDepositTx,
                rw_counter=14,
                call_id=1,
                is_root=True,
                is_create=False,
                code_hash=RLC(EMPTY_CODE_HASH, randomness),
                program_counter=0,
                stack_pointer=1024,
                gas_left=gas_left,
                reversible_write_counter=2,
            ),
            next_step,
        ],
        success=success,
    )
