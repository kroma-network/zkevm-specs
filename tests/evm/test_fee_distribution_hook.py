import pytest

from common import rand_fq
from zkevm_specs.evm_circuit import (
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
    EMPTY_CODE_HASH,
    PROTOCOL_VAULT,
    VALIDATOR_REWARD_VAULT,
    L1_BASE_FEE,
    VALIDATOR_REWARD_SCALAR,
    VALIDATOR_REWARD_DENOMINATOR,
    RLC,
)

CALLEE_ADDRESS = 0xFF

TESTING_DATA = (
    (
        Transaction(
            id=1, caller_address=0xFE, callee_address=CALLEE_ADDRESS, gas=27000, gas_price=int(2e9)
        ),
        1000,
        False,
        False,
        True,
    ),
    (
        Transaction(
            id=2, caller_address=0xFE, callee_address=CALLEE_ADDRESS, gas=27000, gas_price=int(2e9)
        ),
        1000,
        False,
        True,
        False,
    ),
    (
        Transaction(
            id=3, caller_address=0xFE, callee_address=CALLEE_ADDRESS, gas=27000, gas_price=int(2e9)
        ),
        1000,
        True,
        False,
        False,
    ),
)


@pytest.mark.parametrize("tx, gas_left, wrong_fee_amount, wrong_step, success", TESTING_DATA)
def test_fee_distribution_hook(
    tx: Transaction,
    gas_left: int,
    wrong_fee_amount: bool,
    wrong_step: bool,
    success: bool,
):
    randomness = rand_fq()
    block = Block(base_fee=L1_BASE_FEE)

    gas_used = tx.gas - gas_left
    total_reward = tx.gas_price * gas_used if not wrong_fee_amount else 10
    zero_rlc = RLC(0, randomness)

    validator_reward = total_reward * VALIDATOR_REWARD_SCALAR // VALIDATOR_REWARD_DENOMINATOR
    protocol_margin = total_reward - validator_reward
    validator_reward = RLC(validator_reward, randomness)
    protocol_margin = RLC(protocol_margin, randomness)

    rw_dictionary = (
        # fmt: off
        RWDictionary(17)
            .call_context_read(1, CallContextFieldTag.TxId, tx.id)
            .l1_block_read(L1BlockFieldTag.ValidatorRewardScalar, RLC(VALIDATOR_REWARD_SCALAR, randomness))
            .account_write(PROTOCOL_VAULT, AccountFieldTag.Balance, protocol_margin, zero_rlc)
            .account_write(VALIDATOR_REWARD_VAULT, AccountFieldTag.Balance, validator_reward, zero_rlc)
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
                execution_state=ExecutionState.FeeDistributionHook,
                rw_counter=17,
                call_id=1,
                is_root=True,
                is_create=False,
                code_hash=RLC(EMPTY_CODE_HASH, randomness),
                program_counter=0,
                stack_pointer=1024,
                gas_left=gas_left,
                reversible_write_counter=1,
            ),
            StepState(
                execution_state=ExecutionState.ProposerRewardHook
                if not wrong_step
                else ExecutionState.EndTx,
                rw_counter=21,
                call_id=1,
            ),
        ],
        success=success,
    )
