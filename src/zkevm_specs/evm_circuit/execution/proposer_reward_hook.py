from ..instruction import Instruction, Transition
from ..table import (
    CallContextFieldTag,
    L1BlockFieldTag,
    TxContextFieldTag,
)
from ...util import (
    FQ,
    N_BYTES_WORD,
    L1_COST_DENOMINATOR,
    PROPOSER_REWARD_VAULT,
    VALIDATOR_REWARD_DENOMINATOR,
)


def proposer_reward_hook(instruction: Instruction):
    tx_id = instruction.call_context_lookup(CallContextFieldTag.TxId)
    l1_base_fee = instruction.l1_block_read(L1BlockFieldTag.L1BaseFee)
    l1_fee_overhead = instruction.l1_block_read(L1BlockFieldTag.L1FeeOverhead)
    l1_fee_scalar = instruction.l1_block_read(L1BlockFieldTag.L1FeeScalar)
    tx_rollup_data_gas_cost = instruction.rlc_encode(
        instruction.tx_context_lookup(tx_id, TxContextFieldTag.RollupDataGasCost), 32
    )
    zero = instruction.rlc_encode(0, N_BYTES_WORD)

    l1_gas_to_use, _ = instruction.add_words([tx_rollup_data_gas_cost, l1_fee_overhead])
    l1_fee_tmp = instruction.rlc_encode(
        l1_gas_to_use.int_value * l1_base_fee.int_value, N_BYTES_WORD
    )
    instruction.mul_add_words(l1_gas_to_use, l1_base_fee, zero, l1_fee_tmp)

    l1_fee_tmp2 = instruction.rlc_encode(
        l1_fee_tmp.int_value * l1_fee_scalar.int_value, N_BYTES_WORD
    )
    instruction.mul_add_words(l1_fee_tmp, l1_fee_scalar, zero, l1_fee_tmp2)

    l1_fee, l1_cost_remainder = divmod(l1_fee_tmp2.int_value, L1_COST_DENOMINATOR)
    l1_fee_rlc = instruction.rlc_encode(l1_fee, N_BYTES_WORD)
    l1_cost_denominator_rlc = instruction.rlc_encode(L1_COST_DENOMINATOR, N_BYTES_WORD)
    l1_cost_remainder_rlc = instruction.rlc_encode(l1_cost_remainder, N_BYTES_WORD)
    instruction.mul_add_words(
        l1_fee_rlc, l1_cost_denominator_rlc, l1_cost_remainder_rlc, l1_fee_tmp2
    )
    """
    Note(TA): You might think that we should have two constraints as implemented in the zkevm-circuits code:
    1. checking that the remainder is strictly less than the denominator
    2. checking that the denominator has the exact value of 10000.

    However, we do not need constraints here because:
    1. we are using divmod from the stdlib to calculate the quotient and the remainder
    2. we are using L1_COST_DENOMINATOR directly from param.py.
    """

    instruction.add_balance(FQ(PROPOSER_REWARD_VAULT), [l1_fee_rlc])
    instruction.constrain_step_state_transition(rw_counter=Transition.delta(5))
