from ..instruction import Instruction, Transition
from ..table import (
    CallContextFieldTag,
    TxContextFieldTag,
)
from ...util import (
    FQ,
    RLC,
    N_BYTES_WORD,
    PROTOCOL_VAULT,
    VALIDATOR_REWARD_VAULT,
    VALIDATOR_REWARD_SCALAR,
    VALIDATOR_REWARD_DENOMINATOR,
)


def fee_distribution_hook(instruction: Instruction):
    tx_id = instruction.call_context_lookup(CallContextFieldTag.TxId)
    tx_gas = instruction.tx_context_lookup(tx_id, TxContextFieldTag.Gas)
    zero = instruction.rlc_encode(0, N_BYTES_WORD)
    """
    NOTE(TA): You might think that we should have a constraint as implemented in the zkevm-circuits code:
    check that zero is zero.

    However, we do not need constraints here because:
    we are using constant 0 itself.
    """

    tx_gas_price = instruction.tx_gas_price(tx_id)
    gas_used = tx_gas.expr() - instruction.curr.gas_left.expr()
    total_reward, carry = instruction.mul_word_by_u64(tx_gas_price, gas_used)
    instruction.constrain_zero(carry)

    validator_reward_tmp = instruction.rlc_encode(
        total_reward.int_value * VALIDATOR_REWARD_SCALAR, N_BYTES_WORD
    )
    instruction.mul_add_words(
        total_reward, RLC(VALIDATOR_REWARD_SCALAR), zero, validator_reward_tmp
    )

    validator_reward, _ = divmod(validator_reward_tmp.int_value, VALIDATOR_REWARD_DENOMINATOR)
    validator_reward_rlc = instruction.rlc_encode(validator_reward, N_BYTES_WORD)
    protocol_margin_rlc, _ = instruction.sub_word(total_reward, validator_reward_rlc)

    instruction.add_balance(FQ(PROTOCOL_VAULT), [protocol_margin_rlc])
    instruction.add_balance(FQ(VALIDATOR_REWARD_VAULT), [validator_reward_rlc])
    instruction.constrain_step_state_transition(rw_counter=Transition.delta(3))
