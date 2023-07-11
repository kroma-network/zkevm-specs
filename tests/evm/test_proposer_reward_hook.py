import pytest

from common import rand_fq
from zkevm_specs.evm_circuit import (
    AccountFieldTag,
    Block,
    CallContextFieldTag,
    ExecutionState,
    RWDictionary,
    StepState,
    Tables,
    Transaction,
    verify_steps,
)
from zkevm_specs.util import (
    EMPTY_CODE_HASH,
    L1_BASE_FEE,
    L1_COST_DENOMINATOR,
    L1_FEE_OVERHEAD,
    PROPOSER_REWARD_VAULT,
    L1_FEE_SCALAR,
    RLC,
)

CALLEE_ADDRESS = 0xFF

TESTING_DATA = (
    (
        Transaction(
            id=1,
            caller_address=0xFE,
            callee_address=CALLEE_ADDRESS,
            gas=27000,
            gas_price=int(2e9),
        ),
        False,
        False,
        True,
    ),
    (
        Transaction(
            id=2,
            caller_address=0xFE,
            callee_address=CALLEE_ADDRESS,
            gas=27000,
            gas_price=int(2e9),
        ),
        False,
        True,
        False,
    ),
    (
        Transaction(
            id=3,
            caller_address=0xFE,
            callee_address=CALLEE_ADDRESS,
            gas=27000,
            gas_price=int(2e9),
        ),
        True,
        False,
        False,
    ),
)


@pytest.mark.parametrize("tx, wrong_fee, wrong_step, success", TESTING_DATA)
def test_proposer_reward_hook(
    tx: Transaction,
    wrong_fee: bool,
    wrong_step: bool,
    success: bool,
):
    randomness = rand_fq()
    block = Block()

    l1_cost_remainder = 100

    l1_gas_to_use = tx.rollup_data_gas_cost() + L1_FEE_OVERHEAD
    l1_fee_tmp = l1_gas_to_use * L1_BASE_FEE
    l1_fee_tmp2 = l1_fee_tmp * L1_FEE_SCALAR

    fee = int((l1_fee_tmp2 - l1_cost_remainder) / L1_COST_DENOMINATOR) if not wrong_fee else 10
    fee = RLC(fee, randomness, 32)
    zero_rlc = RLC(0, randomness, 32)

    rw_dictionary = (
        # fmt: off
        RWDictionary(17)
            .call_context_read(1, CallContextFieldTag.TxId, tx.id)
            .account_write(PROPOSER_REWARD_VAULT, AccountFieldTag.Balance, fee, zero_rlc)
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
                execution_state=ExecutionState.ProposerRewardHook,
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
                rw_counter=19,
                call_id=1,
            ),
        ],
        success=success,
    )
