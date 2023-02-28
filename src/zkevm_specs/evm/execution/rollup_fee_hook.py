from ..instruction import Instruction, Transition
from ..table import (
    CallContextFieldTag, 
    L1BlockFieldTag,
    TxContextFieldTag, 
)
from ...util import FQ, L1_COST_DENOMINATOR, L1_FEE_RECIPIENT

def rollup_fee_hook(instruction: Instruction):
    tx_id = instruction.call_context_lookup(CallContextFieldTag.TxId) 
    
    l1_base_fee = instruction.l1_block_read(L1BlockFieldTag.L1BaseFee)
    l1_fee_overhead = instruction.l1_block_read(L1BlockFieldTag.L1FeeOverhead)
    l1_fee_scalar = instruction.l1_block_read(L1BlockFieldTag.L1FeeScalar)
    
    tx_rollup_data_gas_cost = instruction.rlc_encode(instruction.tx_context_lookup(tx_id, TxContextFieldTag.RollupDataGasCost), 32)
    l1_gas_to_use, carry = instruction.add_words([tx_rollup_data_gas_cost, l1_fee_overhead])
    
    zero = instruction.rlc_encode(0, 32)
    
    l1_fee_tmp = instruction.rlc_encode(l1_gas_to_use.int_value * l1_base_fee.int_value, 32)
    overflow = instruction.mul_add_words(l1_gas_to_use, l1_base_fee, zero, l1_fee_tmp)
    instruction.constrain_equal(overflow, FQ(0))
    
    l1_fee_tmp2 = instruction.rlc_encode(l1_fee_tmp.int_value * l1_fee_scalar.int_value, 32)
    overflow = instruction.mul_add_words(l1_fee_tmp, l1_fee_scalar, zero, l1_fee_tmp2)
    instruction.constrain_equal(overflow, FQ(0))
    
    l1_fee, l1_cost_remainder = divmod(l1_fee_tmp2.int_value, L1_COST_DENOMINATOR)
    
    l1_fee_rlc = instruction.rlc_encode(l1_fee, 32)
    l1_cost_denominator_rlc = instruction.rlc_encode(L1_COST_DENOMINATOR, 32)
    l1_cost_remainder_rlc = instruction.rlc_encode(l1_cost_remainder, 32)
    
    overflow = instruction.mul_add_words(l1_fee_rlc, l1_cost_denominator_rlc, l1_cost_remainder_rlc, l1_fee_tmp2)
    instruction.constrain_equal(overflow, FQ(0))
    
    instruction.add_balance(FQ(L1_FEE_RECIPIENT), [l1_fee_rlc])
    instruction.constrain_step_state_transition(rw_counter=Transition.delta(5))
