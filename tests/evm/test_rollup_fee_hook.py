import pytest

from zkevm_specs.evm import (
    AccountFieldTag,
    Block,
    CallContextFieldTag,
    ExecutionState,
    L1BlockFieldTag,
    RWDictionary,
    StepState,
    Tables,
    Transaction,
    verify_steps,
)
from zkevm_specs.util import (
    BASE_FEE_RECIPIENT,
    EMPTY_CODE_HASH,
    L1_BASE_FEE,
    L1_COST_DENOMINATOR,
    L1_FEE_OVERHEAD,
    L1_FEE_SCALAR,
    rand_fq, 
    RLC, 
)

CALLEE_ADDRESS = 0xFF

TESTING_DATA = (
    (
        Transaction(
            id=1, caller_address=0xFE, callee_address=CALLEE_ADDRESS, gas=27000, gas_price=int(2e9),
            rollup_data_gas_cost=1000
        ),
        False,
        False,
        True
    ),
    (
        Transaction(
            id=2, caller_address=0xFE, callee_address=CALLEE_ADDRESS, gas=27000, gas_price=int(2e9),
            rollup_data_gas_cost=1000
        ),
        False,
        True,
        False
    ),
        (
        Transaction(
            id=3, caller_address=0xFE, callee_address=CALLEE_ADDRESS, gas=27000, gas_price=int(2e9),
            rollup_data_gas_cost=1000
        ),
        True,
        False,
        False
    ),
)

@pytest.mark.parametrize(
    "tx, wrong_fee, wrong_step, success", TESTING_DATA
)
def test_rollup_fee_hook(
    tx: Transaction,
    wrong_fee: bool,
    wrong_step: bool,
    success: bool,
):
    randomness = rand_fq()
    block = Block()
    
    l1_cost_remainder = 100
    
    l1_gas_to_use = tx.rollup_data_gas_cost + L1_FEE_OVERHEAD
    l1_fee_tmp = l1_gas_to_use * L1_BASE_FEE
    l1_fee_tmp2 = l1_fee_tmp * L1_FEE_SCALAR
    
    fee = int((l1_fee_tmp2 - l1_cost_remainder)/L1_COST_DENOMINATOR) if not wrong_fee else 10
    fee = RLC(fee, randomness, 32)
    zero_rlc = RLC(0, randomness, 32)
    
    rw_dictionary = (
        # fmt: off
        RWDictionary(17)
            .call_context_read(1, CallContextFieldTag.TxId, tx.id)
            .l1_block_read(L1BlockFieldTag.L1BaseFee, RLC(L1_BASE_FEE, randomness, 32))
            .l1_block_read(L1BlockFieldTag.L1FeeOverhead, RLC(L1_FEE_OVERHEAD, randomness, 32))
            .l1_block_read(L1BlockFieldTag.L1FeeScalar, RLC(L1_FEE_SCALAR, randomness, 32))
            .account_write(BASE_FEE_RECIPIENT, AccountFieldTag.Balance, fee, zero_rlc)
        # fmt: on
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
                execution_state=ExecutionState.RollupFeeHook,
                rw_counter=17,
                call_id=1,
                is_root=True,
                is_create=False,
                code_hash=RLC(EMPTY_CODE_HASH, randomness),
                program_counter=0,
                stack_pointer=1024,
                reversible_write_counter=1,
            ),
            StepState(
                execution_state=ExecutionState.EndTx if not wrong_step else ExecutionState.BeginTx,
                rw_counter=22,
                call_id=1,
            ),
        ],
        success=success,
    )
